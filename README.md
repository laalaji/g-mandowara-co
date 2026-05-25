# G Mandowara & Co. — Website

Static marketing site for **G Mandowara & Co., Chartered Accountants** (Est. 1973).

Live (GitHub Pages): https://laalaji.github.io/g-mandowara-co/

## Pages (7)

- `index.html` — Home: hero, intro, milestones, guiding pillars, CTA
- `about.html` — About the firm: leadership, vision, mission, five core values
- `services.html` — Ten professional services + "why businesses trust us"
- `team.html` — Partners / Our Team: five partner profiles
- `career.html` — Career: secure CV-upload application form
- `articles.html` — Articles / News / Publications (coming soon)
- `contact.html` — Contact: secure enquiry form + contact details

## Stack

Hand-coded HTML5 / CSS3 / vanilla JS — no front-end framework, no CMS, no build step.

- Typography: Cormorant Garamond (display) + Inter (body) via Google Fonts
- Animations: [AOS 2.3.4](https://github.com/michalsnik/aos) via jsDelivr (pinned + SRI-hashed)
- Imagery: Unsplash CDN; brand favicon + logo generated from the CA mark
- Backend: `app.py` — hardened **Flask** app serving the site + form APIs

## Two deployment modes

| | GitHub Pages (static) | VPS (Flask) |
|---|---|---|
| All 7 pages render | ✓ | ✓ |
| Contact / Career forms submit | ✗ (no backend) | ✓ |

The Contact and Career forms need the Flask backend (`/api/*`), so the
**fully functional** deployment is the VPS. GitHub Pages is a static showcase.

## Run the backend (VPS / local)

```bash
python3 -m venv venv && ./venv/bin/pip install flask gunicorn

# production (recommended) — gunicorn, sanitised Server banner, 1 worker + threads
GMC_SECRET="$(openssl rand -hex 32)" ./venv/bin/gunicorn -c gunicorn.conf.py app:app

# development
GMC_PORT=8080 ./venv/bin/python app.py
```

Optional environment variables:

| Var | Purpose | Default |
|---|---|---|
| `GMC_SECRET` | HMAC key for CSRF/captcha signing | random per start |
| `GMC_PORT` | Listen port | `8080` |
| `GMC_RATE_MAX` / `GMC_RATE_WINDOW` | Rate limit (submits / seconds per IP) | `5` / `60` |
| `GMC_UPLOAD_DIR` | Where CVs are stored (outside web root) | `./uploads` |
| `SMTP_HOST` `SMTP_PORT` `SMTP_USER` `SMTP_PASS` `SMTP_FROM` `GMC_NOTIFY_EMAIL` | Email forwarding of submissions | logging only |

`server.py` (static-only, no forms) is retained as a lightweight fallback.

## Security posture

- Strict route allowlist + extension allowlist (no source-code exposure, no dotfiles, no directory listing)
- Path-traversal protection
- Response headers on every reply: CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP
- SRI hashes on every external script and stylesheet
- AOS pinned to 2.3.4 — no known CVEs
- Banner sanitised (`Server: GMC/1.0`)
- 404 page is non-verbose (no path leaks)

### Form security (Flask)

- Stateless HMAC-signed **CSRF** token + **math captcha** (single-use via replay cache)
- **Honeypot** field
- Per-IP **rate limiting**
- Strict input validation, length caps, control-char stripping
- **CV upload**: extension allowlist (`pdf/doc/docx`) + **magic-byte sniffing** + 5 MB cap + randomised UUID filename; stored **outside the web root** and never served back
- Submissions logged to JSONL outside the web root; optional SMTP forwarding

All controls verified by `test_backend.py` (50 checks) and `test_e2e.py`
(render + live form submission). Both excluded from the repo.

## Project status

Slices 1–2 of the engagement (quotation QTN/WEB/2026/GMC-001).
Pending: real contact details + Google Map, WhatsApp number, social handles,
Google Analytics 4, and Articles content.
