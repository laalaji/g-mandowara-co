# G Mandowara & Co. — Website

Static marketing site for **G Mandowara & Co., Chartered Accountants** (Est. 1973).

Live (GitHub Pages): https://laalaji.github.io/g-mandowara-co/

## Pages

- `index.html` — Home: hero, intro, milestones, guiding pillars, CTA
- `about.html` — About the firm: leadership, vision, mission, five core values
- `services.html` — Ten professional services + "why businesses trust us"

## Stack

Hand-coded HTML5 / CSS3 / vanilla JS — no framework, no CMS, no build step.

- Typography: Cormorant Garamond (display) + Inter (body) via Google Fonts
- Animations: [AOS 2.3.4](https://github.com/michalsnik/aos) via jsDelivr (pinned + SRI-hashed)
- Imagery: Unsplash CDN
- Self-hosted helper: `server.py` — hardened Python static server with OWASP-aligned headers (for local / VPS use; GitHub Pages doesn't run it)

## Run locally

```bash
python3 server.py          # serves on http://127.0.0.1:8080
# or
GMC_PORT=8000 python3 server.py
# drop root privileges (production):
SETUID_USER=nobody python3 server.py
```

## Security posture

- Strict route allowlist + extension allowlist (no source-code exposure, no dotfiles, no directory listing)
- Path-traversal protection
- HTTP method allowlist (only GET / HEAD)
- Response headers: CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP
- SRI hashes on every external script and stylesheet
- AOS pinned to 2.3.4 — no known CVEs
- Banner sanitised (`Server: GMC/1.0`)
- 404 page is non-verbose (no path leaks)

## Project status

Slice 1 of a larger engagement (per quotation QTN/WEB/2026/GMC-001).
Pending in later slices: Contact / Inquiry form (honeypot + math captcha),
Google Analytics 4, advanced on-page SEO, WhatsApp number, social handles.
