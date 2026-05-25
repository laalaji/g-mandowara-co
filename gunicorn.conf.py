"""Gunicorn config for G Mandowara & Co."""
import gunicorn

# Sanitise the Server banner (avoid leaking gunicorn version)
gunicorn.SERVER_SOFTWARE = "GMC/1.0"
gunicorn.SERVER = "GMC/1.0"

bind = "0.0.0.0:8080"
workers = 1            # single worker keeps in-memory rate-limit / captcha state consistent
threads = 4            # concurrency via threads
worker_class = "gthread"
timeout = 30
keepalive = 5
limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 8190
accesslog = "-"
errorlog = "-"
loglevel = "info"
proc_name = "gmc-web"
