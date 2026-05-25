#!/usr/bin/env python3
"""
G Mandowara & Co. — hardened Flask application.

Serves the static site (OWASP-aligned headers, route allowlist) and provides
secure form endpoints:

  GET  /api/form-init   -> stateless CSRF token + math-captcha challenge
  POST /api/contact     -> validated contact submission (honeypot + captcha + CSRF)
  POST /api/career      -> validated CV upload (type/magic-byte/size, random name,
                           stored OUTSIDE web root, never served back)

Security controls:
  * Per-IP rate limiting (in-memory token buckets)
  * Stateless HMAC-signed CSRF + captcha (single-use captcha via replay cache)
  * Strict input validation + length caps + control-char stripping
  * File upload: extension allowlist + magic-byte sniffing + size cap +
    randomized UUID filename + storage outside the served directory
  * Submissions logged to JSONL outside web root; SMTP forwarding if configured
  * Security headers on every response (CSP, HSTS, XFO, etc.)
"""
import os
import re
import json
import hmac
import time
import uuid
import base64
import hashlib
import secrets
import smtplib
import threading
from email.message import EmailMessage
from datetime import datetime, timezone

from flask import Flask, request, jsonify, send_from_directory, abort, Response

# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.environ.get("GMC_UPLOAD_DIR", os.path.join(BASE_DIR, "uploads"))      # NOT served
DATA_DIR = os.environ.get("GMC_DATA_DIR", os.path.join(BASE_DIR, "submissions"))      # NOT served
PORT = int(os.environ.get("GMC_PORT", "8080"))
SECRET = os.environ.get("GMC_SECRET", "").encode() or secrets.token_bytes(32)
MAX_UPLOAD = 5 * 1024 * 1024          # 5 MB CV cap
TOKEN_TTL = 1800                      # 30 min for csrf/captcha
RATE_MAX = int(os.environ.get("GMC_RATE_MAX", "5"))         # submissions
RATE_WINDOW = int(os.environ.get("GMC_RATE_WINDOW", "60"))  # per N s per IP

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

ALLOWED_FILES = {
    "/", "/index.html", "/about.html", "/services.html", "/team.html",
    "/career.html", "/articles.html", "/contact.html",
    "/robots.txt", "/sitemap.xml", "/favicon.ico",
}
ALLOWED_PREFIXES = ("/assets/",)
ALLOWED_EXTS = (".html", ".css", ".js", ".svg", ".png", ".jpg", ".jpeg",
                ".webp", ".woff", ".woff2", ".ico", ".txt", ".xml")

# CV upload: extension -> list of acceptable magic-byte prefixes
CV_TYPES = {
    "pdf":  [b"%PDF"],
    "doc":  [b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"],          # OLE2 (legacy .doc)
    "docx": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],   # ZIP container
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

CSP = (
    "default-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data: https://images.unsplash.com https://plus.unsplash.com; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "connect-src 'self'; "
    "frame-src https://www.google.com https://maps.google.com; "
    "object-src 'none'; base-uri 'self'; "
    "form-action 'self'; frame-ancestors 'none'"
)

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD + 512 * 1024  # hard request cap

_lock = threading.Lock()
_rate = {}            # ip -> [timestamps]
_used_captcha = {}    # captcha_id -> expiry (replay prevention)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _sign(msg: bytes) -> str:
    return base64.urlsafe_b64encode(hmac.new(SECRET, msg, hashlib.sha256).digest()).decode().rstrip("=")


def make_csrf() -> str:
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(8)
    payload = f"{ts}.{nonce}"
    return f"{payload}.{_sign(payload.encode())}"


def check_csrf(token: str) -> bool:
    try:
        ts, nonce, sig = token.split(".", 2)
    except (ValueError, AttributeError):
        return False
    if not hmac.compare_digest(sig, _sign(f"{ts}.{nonce}".encode())):
        return False
    return (int(time.time()) - int(ts)) <= TOKEN_TTL


def make_captcha():
    a, b = secrets.randbelow(9) + 1, secrets.randbelow(9) + 1
    ts = str(int(time.time()))
    answer = str(a + b)
    payload = f"{answer}.{ts}.{secrets.token_urlsafe(6)}"
    cid = f"{payload}.{_sign(payload.encode())}"
    return f"{a} + {b}", cid


def check_captcha(cid: str, supplied: str) -> bool:
    try:
        answer, ts, nonce, sig = cid.split(".", 3)
    except (ValueError, AttributeError):
        return False
    if not hmac.compare_digest(sig, _sign(f"{answer}.{ts}.{nonce}".encode())):
        return False
    if (int(time.time()) - int(ts)) > TOKEN_TTL:
        return False
    now = time.time()
    with _lock:
        # purge expired replay entries
        for k in [k for k, v in _used_captcha.items() if v < now]:
            _used_captcha.pop(k, None)
        if cid in _used_captcha:
            return False  # already used
        ok = (supplied or "").strip() == answer
        if ok:
            _used_captcha[cid] = now + TOKEN_TTL
        return ok


def rate_ok(ip: str) -> bool:
    now = time.time()
    with _lock:
        bucket = [t for t in _rate.get(ip, []) if now - t < RATE_WINDOW]
        if len(bucket) >= RATE_MAX:
            _rate[ip] = bucket
            return False
        bucket.append(now)
        _rate[ip] = bucket
        return True


def clean(val, maxlen):
    s = CONTROL_RE.sub("", (val or "").strip())
    return s[:maxlen]


def client_ip():
    # Behind a reverse proxy, trust the first X-Forwarded-For hop if present.
    xff = request.headers.get("X-Forwarded-For", "")
    return (xff.split(",")[0].strip() if xff else request.remote_addr) or "unknown"


def log_submission(kind, record):
    record["_ts"] = datetime.now(timezone.utc).isoformat()
    record["_ip"] = client_ip()
    path = os.path.join(DATA_DIR, f"{kind}.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def try_email(subject, body):
    host = os.environ.get("SMTP_HOST")
    to_addr = os.environ.get("GMC_NOTIFY_EMAIL")
    if not host or not to_addr:
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = os.environ.get("SMTP_FROM", "noreply@ca-gmc.com")
        msg["To"] = to_addr
        msg.set_content(body)
        port = int(os.environ.get("SMTP_PORT", "587"))
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.starttls()
            user = os.environ.get("SMTP_USER")
            pwd = os.environ.get("SMTP_PASS")
            if user and pwd:
                s.login(user, pwd)
            s.send_message(msg)
        return True
    except Exception:
        return False


# ----------------------------------------------------------------------
# Security headers
# ----------------------------------------------------------------------
@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Server"] = "GMC/1.0"
    return resp


# ----------------------------------------------------------------------
# Static serving (allowlist)
# ----------------------------------------------------------------------
def _allowed_path(path: str) -> bool:
    if not path.startswith("/") or "//" in path or "\\" in path:
        return False
    parts = path.split("/")
    if any(seg in ("..", ".") for seg in parts):
        return False
    if any(seg.startswith(".") and seg not in ("",) for seg in parts):
        # allow /favicon.ico (no leading dot); block dotfiles like /.git
        if path != "/favicon.ico":
            return False
    if path in ALLOWED_FILES:
        return True
    if any(path.startswith(p) for p in ALLOWED_PREFIXES) and path.endswith(ALLOWED_EXTS):
        return True
    return False


@app.route("/", defaults={"reqpath": ""})
@app.route("/<path:reqpath>")
def static_router(reqpath):
    path = "/" + reqpath
    if path == "/":
        path = "/index.html"
    if not _allowed_path(path):
        abort(404)
    rel = path.lstrip("/")
    full = os.path.join(BASE_DIR, rel)
    if not os.path.isfile(full):
        abort(404)
    resp = send_from_directory(BASE_DIR, rel)
    if rel.endswith((".css", ".js", ".svg", ".woff", ".woff2", ".ico", ".png", ".jpg", ".jpeg", ".webp")):
        resp.headers["Cache-Control"] = "public, max-age=3600"
    else:
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ----------------------------------------------------------------------
# API
# ----------------------------------------------------------------------
@app.route("/api/form-init", methods=["GET"])
def form_init():
    question, cid = make_captcha()
    return jsonify({
        "csrf_token": make_csrf(),
        "captcha_id": cid,
        "captcha_question": question,
    })


def _precheck():
    """Shared validation. Returns (error_message or None)."""
    ip = client_ip()
    if not rate_ok(ip):
        return "Too many submissions. Please wait a minute and try again.", 429
    if (request.form.get("company") or "").strip():
        return "Submission blocked.", 400          # honeypot tripped
    if not check_csrf(request.form.get("csrf_token", "")):
        return "Your session expired. Please refresh the page and try again.", 403
    if not check_captcha(request.form.get("captcha_id", ""), request.form.get("captcha_answer", "")):
        return "Incorrect captcha answer. Please try again.", 400
    return None


@app.route("/api/contact", methods=["POST"])
def contact():
    err = _precheck()
    if err:
        return jsonify({"ok": False, "error": err[0]}), err[1]

    name = clean(request.form.get("name"), 80)
    email = clean(request.form.get("email"), 120)
    phone = clean(request.form.get("phone"), 20)
    subject = clean(request.form.get("subject"), 120)
    message = clean(request.form.get("message"), 2000)

    if not name or not email or not subject or not message:
        return jsonify({"ok": False, "error": "Please fill in all required fields."}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"ok": False, "error": "Please enter a valid email address."}), 400
    if phone and not re.match(r"^[0-9+\-\s()]{6,20}$", phone):
        return jsonify({"ok": False, "error": "Please enter a valid phone number."}), 400

    record = {"type": "contact", "name": name, "email": email, "phone": phone,
              "subject": subject, "message": message}
    log_submission("contact", record)
    try_email(f"[Website] Contact: {subject}",
              f"Name: {name}\nEmail: {email}\nPhone: {phone}\n\n{message}")

    return jsonify({"ok": True, "message": "Thank you! Your message has been received. We'll be in touch shortly."})


@app.route("/api/career", methods=["POST"])
def career():
    err = _precheck()
    if err:
        return jsonify({"ok": False, "error": err[0]}), err[1]

    name = clean(request.form.get("name"), 80)
    email = clean(request.form.get("email"), 120)
    phone = clean(request.form.get("phone"), 20)
    role = clean(request.form.get("role"), 80)

    if not name or not email:
        return jsonify({"ok": False, "error": "Name and email are required."}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"ok": False, "error": "Please enter a valid email address."}), 400

    f = request.files.get("cv")
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "Please attach your CV (PDF, DOC, or DOCX)."}), 400

    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in CV_TYPES:
        return jsonify({"ok": False, "error": "Unsupported file type. Upload PDF, DOC, or DOCX."}), 400

    head = f.stream.read(8)
    f.stream.seek(0)
    if not any(head.startswith(sig) for sig in CV_TYPES[ext]):
        return jsonify({"ok": False, "error": "File content does not match its extension."}), 400

    # Enforce size precisely (independent of Content-Length spoofing)
    data = f.stream.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        return jsonify({"ok": False, "error": "File is too large. Maximum size is 5 MB."}), 413
    if len(data) == 0:
        return jsonify({"ok": False, "error": "Uploaded file is empty."}), 400

    # Random server-controlled filename; user filename never used in path
    stored = f"{uuid.uuid4().hex}.{ext}"
    dest = os.path.join(UPLOAD_DIR, stored)
    with open(dest, "wb") as out:
        out.write(data)
    os.chmod(dest, 0o600)

    record = {"type": "career", "name": name, "email": email, "phone": phone,
              "role": role, "cv_stored": stored, "cv_original": clean(f.filename, 200),
              "cv_size": len(data)}
    log_submission("career", record)
    try_email(f"[Website] CV: {name}",
              f"Name: {name}\nEmail: {email}\nPhone: {phone}\nRole: {role}\nFile: {stored} ({len(data)} bytes)")

    return jsonify({"ok": True, "message": "Thank you! Your application and CV have been received."})


@app.errorhandler(404)
def not_found(_e):
    return Response("Not Found", status=404, mimetype="text/plain")


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"ok": False, "error": "File is too large. Maximum size is 5 MB."}), 413


@app.errorhandler(429)
def too_many(_e):
    return jsonify({"ok": False, "error": "Too many requests. Please slow down."}), 429


if __name__ == "__main__":
    # Production note: run behind gunicorn + TLS-terminating reverse proxy.
    app.run(host="0.0.0.0", port=PORT, threaded=True)
