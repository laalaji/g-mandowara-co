#!/usr/bin/env python3
"""
G Mandowara & Co. — hardened static site server.

Security posture:
- Allowlists by file extension + explicit path whitelist (HTML pages, assets,
  robots.txt, sitemap.xml). Everything else returns 404.
- Directory listing disabled.
- Blocks dotfiles (.git, .env), source code (.py), docs (.md, .docx, .pdf),
  test artifacts.
- OWASP-aligned response headers on every response.
- Strips fingerprinting Server/Date trivia where reasonable.
- Drops privileges to a non-root user when started as root and SETUID_USER env
  is set (best-effort; pass SETUID_USER=nobody to enable).
"""
import http.server
import socketserver
import os
import sys
import signal
import pwd

PORT = int(os.environ.get("GMC_PORT", "8080"))
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

CSP = (
    "default-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data: https://images.unsplash.com https://plus.unsplash.com; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

# Public surface — anything not matching is 404.
ALLOWED_FILES = {"/", "/index.html", "/about.html", "/services.html", "/robots.txt", "/sitemap.xml"}
ALLOWED_PREFIXES = ("/assets/",)
ALLOWED_EXTS = (".html", ".css", ".js", ".svg", ".png", ".jpg", ".jpeg", ".webp",
                ".woff", ".woff2", ".ico", ".txt", ".xml")


class SecureHandler(http.server.SimpleHTTPRequestHandler):
    server_version = "GMC/1.0"
    sys_version = ""  # strip "Python/X.Y.Z"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    # --- Disable directory listing ---
    def list_directory(self, path):
        self.send_error(404, "Not Found")
        return None

    # --- Header injection ---
    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", CSP)
        # HSTS — browsers that ever see HTTPS will pin it.
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        # Caching
        raw = getattr(self, "path", "") or ""
        p = raw.split("?", 1)[0]
        if p.endswith((".css", ".js", ".svg", ".woff", ".woff2", ".ico", ".png", ".jpg", ".jpeg", ".webp")):
            self.send_header("Cache-Control", "public, max-age=3600")
        else:
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    # --- Strip default Server header date echoing ---
    def version_string(self):
        return self.server_version

    # --- Strict request routing ---
    def do_GET(self):
        if not self._allowed():
            self.send_error(404, "Not Found")
            return
        if self.path in ("", "/"):
            self.path = "/index.html"
        return super().do_GET()

    def do_HEAD(self):
        if not self._allowed():
            self.send_error(404, "Not Found")
            return
        if self.path in ("", "/"):
            self.path = "/index.html"
        return super().do_HEAD()

    def _allowed(self):
        raw = (self.path or "").split("?", 1)[0]
        # Reject anything weird
        if not raw.startswith("/") or "//" in raw or "\\" in raw:
            return False
        # Block path-traversal attempts (defence-in-depth; SimpleHTTPRequestHandler
        # already collapses these but we refuse outright).
        parts = raw.split("/")
        if any(seg in ("..", ".") for seg in parts):
            return False
        # Block dotfiles / dotdirs
        if any(seg.startswith(".") for seg in parts if seg):
            return False
        # Exact-file allowlist
        if raw in ALLOWED_FILES:
            return True
        # Asset path allowlist
        if any(raw.startswith(pref) for pref in ALLOWED_PREFIXES) and raw.endswith(ALLOWED_EXTS):
            return True
        return False

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))


def maybe_drop_privileges():
    """Drop root to SETUID_USER if running as root and env is set."""
    user = os.environ.get("SETUID_USER")
    if user and os.geteuid() == 0:
        try:
            entry = pwd.getpwnam(user)
            os.setgid(entry.pw_gid)
            os.setuid(entry.pw_uid)
            sys.stderr.write("Dropped privileges to %s\n" % user)
        except (KeyError, PermissionError) as e:
            sys.stderr.write("Could not drop to %s: %s\n" % (user, e))


def main():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), SecureHandler) as httpd:
        maybe_drop_privileges()

        def shutdown(_signum, _frame):
            sys.stderr.write("\nShutting down...\n")
            sys.exit(0)
        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)

        sys.stderr.write("G Mandowara & Co. serving on 0.0.0.0:%d (uid=%d)\n" % (PORT, os.geteuid()))
        sys.stderr.write("Directory: %s\n" % DIRECTORY)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
