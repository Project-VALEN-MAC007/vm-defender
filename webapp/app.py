"""Company web application (production and honeypot run the same code).

    BACKEND=real  python3 -m webapp.app   # production server
    BACKEND=decoy python3 -m webapp.app   # honeypot data set

Standard-library HTTP server. Public pages are identical across backends; only
the data (accounts, shipments, contact store) differs. No real secrets live in
the code, and the honeypot backend is fully isolated fake data.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import re
import secrets
import threading
from urllib.parse import parse_qs, urlsplit

from . import content
from .backends import load as load_backend

SESSION_COOKIE = "alsid"
TOKEN_PATTERN = re.compile(r"^[0-9a-f]{32}$")


class Sessions:
    def __init__(self):
        self._lock = threading.Lock()
        self._store: dict[str, str] = {}

    def create(self, username: str) -> str:
        token = secrets.token_hex(16)
        with self._lock:
            self._store[token] = username
        return token

    def user(self, token: str | None):
        if not token:
            return None
        with self._lock:
            return self._store.get(token)

    def drop(self, token: str | None):
        if not token:
            return
        with self._lock:
            self._store.pop(token, None)


def handler_factory(backend, sessions: Sessions):
    def year() -> int:
        return datetime.now(timezone.utc).year

    class Handler(BaseHTTPRequestHandler):
        server_version = "nginx"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def version_string(self):
            # Front Nginx overwrites this in the lab; keep it generic regardless.
            return "nginx"

        def log_message(self, *args):
            pass

        def _cookie_token(self):
            raw = self.headers.get("Cookie", "")
            for part in raw.split(";"):
                key, _, value = part.strip().partition("=")
                if key == SESSION_COOKIE:
                    return value.strip()
            return None

        def _send(self, status, body, content_type="text/html; charset=utf-8", extra=None):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _page(self, status, title, body):
            self._send(status, content.page(backend.company, title, body, year()))

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/robots.txt":
                self._send(200, content.ROBOTS_TXT, "text/plain; charset=utf-8")
                return
            if path == "/static/site.css":
                self._send(200, content.SITE_CSS, "text/css; charset=utf-8")
                return
            if path == "/":
                self._page(200, "Home", content.home(backend.company)); return
            if path == "/about":
                self._page(200, "About", content.about(backend.company)); return
            if path == "/services":
                self._page(200, "Services", content.services(backend.company)); return
            if path == "/news":
                self._page(200, "News", content.news_index(backend.company, backend.articles)); return
            if path.startswith("/news/"):
                article = backend.article(path[len("/news/"):])
                if article:
                    self._page(200, article["title"], content.news_article(backend.company, article)); return
                self._page(404, "Not found", content.NOT_FOUND_BODY); return
            if path == "/contact":
                self._page(200, "Contact", content.contact(backend.company)); return
            if path == "/login":
                self._page(200, "Sign in", content.login(backend.company)); return
            if path == "/logout":
                self.sessions_drop(); return
            if path == "/portal":
                self.render_portal(); return
            if path == "/healthz":
                self._send(200, "ok", "text/plain; charset=utf-8"); return
            self._page(404, "Not found", content.NOT_FOUND_BODY)

        sessions_obj = sessions

        def sessions_drop(self):
            self.sessions_obj.drop(self._cookie_token())
            self._send(303, "", extra={"Location": "/login",
                       "Set-Cookie": f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"})

        def render_portal(self):
            token = self._cookie_token()
            username = self.sessions_obj.user(token)
            if (not username and backend.session_fallback_user and token
                    and TOKEN_PATTERN.match(token)):
                username = backend.session_fallback_user
            account = backend.accounts.get(username) if username else None
            if not account:
                self._send(303, "", extra={"Location": "/login"}); return
            self._page(200, "Customer portal",
                       content.portal(backend.company, account["display_name"], account["shipments"]))

        def _form(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            return {k: v[0] for k, v in parse_qs(raw).items()}

        def do_POST(self):
            path = urlsplit(self.path).path
            if path == "/contact":
                form = self._form()
                name = (form.get("name") or "").strip()
                if name and form.get("email") and form.get("message"):
                    backend.record_contact(name, form.get("email", ""), form.get("message", ""))
                    self._page(200, "Contact", content.contact(backend.company, sent=True, name=name)); return
                self._page(400, "Contact", content.contact(backend.company)); return
            if path == "/login":
                form = self._form()
                account = backend.verify(form.get("username", ""), form.get("password", ""))
                if account:
                    token = self.sessions_obj.create(form.get("username", "").strip())
                    self._send(303, "", extra={"Location": "/portal",
                               "Set-Cookie": f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax"})
                    return
                self._page(401, "Sign in", content.login(backend.company, "Invalid username or password.")); return
            self._page(404, "Not found", content.NOT_FOUND_BODY)

    return Handler


def build(backend_name: str | None = None):
    backend = load_backend(backend_name or os.environ.get("BACKEND", "decoy"))
    return handler_factory(backend, Sessions()), backend


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default=os.environ.get("WEBAPP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("WEBAPP_PORT", "8080")))
    parser.add_argument("--backend", default=os.environ.get("BACKEND", "decoy"))
    args = parser.parse_args(argv)
    handler, backend = build(args.backend)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    server.daemon_threads = True
    print(f"company web app backend={backend.name} on http://{args.host}:{args.port}/", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
