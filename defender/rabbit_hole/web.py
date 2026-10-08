"""Web side of Rabbit Hole: an HTTP decoy that serves chained resources.

``WebEngine`` holds all decision logic and is independent of the socket layer
so it can be unit-tested and used by the demo generator. ``serve`` wraps it in
a small threaded HTTP server that sits behind the Defender's Nginx.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Callable
from urllib.parse import parse_qsl, unquote, urlsplit

from .config import RabbitConfig, load
from .render import Faker, render

MAX_BODY = 65536
LOGGED_PAYLOAD = 4096
SESSION_COOKIE = "PHPSESSID"
SID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
MASKED_HEADERS = {"cookie", "authorization", "proxy-authorization"}
DROPPED_HEADERS = {"x-real-ip", "x-real-port", "x-forwarded-for", "x-forwarded-port",
                   "x-forwarded-proto", "x-request-id"}
ACTIONS = {"listing": "list_directory", "file": "read_file", "api": "call_api",
           "people_api": "call_api", "form": "open_page"}

NOT_FOUND = ("<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n"
             "<center><h1>404 Not Found</h1></center>\r\n<hr><center>{server}</center>\r\n"
             "</body>\r\n</html>\r\n")
FORBIDDEN = NOT_FOUND.replace("404 Not Found", "403 Forbidden")
NOT_ALLOWED = NOT_FOUND.replace("404 Not Found", "405 Not Allowed")
TOO_LARGE = NOT_FOUND.replace("404 Not Found", "413 Request Entity Too Large")


@dataclass
class SessionState:
    id: str
    created: float
    last_seen: float
    revealed: dict = field(default_factory=dict)
    accessed: list = field(default_factory=list)
    limit_reached: bool = False


@dataclass
class Response:
    status: int
    headers: dict
    body: bytes
    event: dict


class WebEngine:
    def __init__(self, config: RabbitConfig, clock: Callable[[], float] | None = None,
                 today=None):
        self.config_path = config.path
        self.clock = clock or time.time
        self.today = today
        self.lock = threading.RLock()
        self.sessions: "OrderedDict[str, SessionState]" = OrderedDict()
        self.api_keys: "OrderedDict[str, str]" = OrderedDict()
        self._mtime = None
        self._apply(config)

    # -- configuration -------------------------------------------------
    def _apply(self, config: RabbitConfig) -> None:
        self.config = config
        self.secret = config.secret()
        self.scenarios = config.selected("web")
        self.deployment = config.deployment_faker(self.today)
        self.routes = {}
        self.fillers = set()
        for scenario in self.scenarios:
            for node in scenario.nodes.values():
                self.routes[node.path] = (scenario, node)
                for name in node.filler:
                    if node.kind == "listing":
                        self.fillers.add(node.path + render(name, self.deployment, {}))
        self.trusted = [ipaddress.ip_network(c, strict=False)
                        for c in config.web.get("trusted_proxies") or []]
        self.server_header = str(config.web.get("server_header") or "nginx")
        self._mtime = self._signature(config)

    def _signature(self, config: RabbitConfig) -> tuple:
        mtime = self.config_path.stat().st_mtime if self.config_path and self.config_path.is_file() else None
        return (mtime, config.scenario_signature())

    def maybe_reload(self) -> None:
        """Pick up dashboard changes (config or scenario files) without restarting;
        keep the old config on errors."""
        if not self.config_path or not self.config_path.is_file():
            return
        mtime = self._signature(self.config)
        if mtime == self._mtime:
            return
        try:
            fresh = load(self.config_path, self.config.root)
            if fresh.problems():
                raise ValueError("invalid rabbit hole config")
            with self.lock:
                self._apply(fresh)
        except (ValueError, OSError, KeyError):
            self._mtime = mtime

    # -- sessions ------------------------------------------------------
    def _session_faker(self, sid: str) -> Faker:
        return Faker(self.secret, "web:" + sid, self.config.organization, self.today)

    def _fallback_sid(self, ip: str, agent: str) -> str:
        message = f"fallback|{ip}|{agent}".encode("utf-8")
        return hmac.new(self.secret, message, hashlib.sha256).hexdigest()[:32]

    def _session(self, sid: str, now: float) -> SessionState:
        limits = self.config.limits
        cutoff = now - limits["session_ttl_seconds"]
        while self.sessions:
            oldest = next(iter(self.sessions.values()))
            if oldest.last_seen >= cutoff and len(self.sessions) < limits["max_sessions"]:
                break
            self.sessions.popitem(last=False)
        state = self.sessions.get(sid)
        if state is None:
            state = SessionState(sid, now, now)
            self.sessions[sid] = state
        self.sessions.move_to_end(sid)
        state.last_seen = now
        return state

    def _api_key_owner(self, value: str) -> str | None:
        return self.api_keys.get(value) if value else None

    def _remember_key(self, key: str, sid: str) -> None:
        self.api_keys[key] = sid
        self.api_keys.move_to_end(key)
        while len(self.api_keys) > self.config.limits["max_sessions"]:
            self.api_keys.popitem(last=False)

    # -- request handling ----------------------------------------------
    def client_address(self, peer_ip: str, headers: dict) -> tuple:
        try:
            peer = ipaddress.ip_address(peer_ip)
        except ValueError:
            return peer_ip, None, False
        if any(peer in network for network in self.trusted):
            real = headers.get("x-real-ip", "").strip()
            try:
                ipaddress.ip_address(real)
                port = headers.get("x-real-port", "").strip()
                return real, int(port) if port.isdigit() else None, True
            except ValueError:
                pass
        return peer_ip, None, False

    def handle(self, method: str, target: str, headers: dict, body: bytes,
               peer: tuple, local: tuple) -> Response:
        self.maybe_reload()
        with self.lock:
            return self._handle(method.upper(), target, {k.lower(): v for k, v in headers.items()},
                                body, peer, local)

    def _handle(self, method, target, headers, body, peer, local) -> Response:
        now = self.clock()
        source_ip, source_port, proxied = self.client_address(peer[0], headers)
        if source_port is None and not proxied:
            source_port = peer[1]
        split = urlsplit(target)
        path = re.sub(r"/{2,}", "/", unquote(split.path or "/"))
        agent = headers.get("user-agent", "")
        cookie_sid = _cookie(headers.get("cookie", ""), SESSION_COOKIE)
        if cookie_sid and SID_PATTERN.match(cookie_sid):
            sid, link = cookie_sid, "cookie"
        else:
            sid, link = self._fallback_sid(source_ip, agent), "ip_ua"
        state = self._session(sid, now)
        faker = self._session_faker(sid)
        event = {
            "timestamp": datetime.fromtimestamp(now, timezone.utc).isoformat(),
            "event": "rabbit_hole.web", "profile": "rabbithole",
            "protocol": headers.get("x-forwarded-proto", "http").lower()[:8] if proxied else "http",
            "session_id": sid, "link": link, "linked_session": None,
            "request_id": headers.get("x-request-id") if proxied else None,
            "source_ip": source_ip, "source_port": source_port,
            "dest_ip": local[0], "dest_port": _int(headers.get("x-forwarded-port")) if proxied else local[1],
            "method": method, "path": path, "query": split.query[:1024],
            "headers": _log_headers(headers), "user_agent": agent[:512],
            "referer": headers.get("referer", "")[:512] or None,
            "payload": body[:LOGGED_PAYLOAD].decode("utf-8", errors="replace") if body else "",
            "payload_truncated": len(body) > LOGGED_PAYLOAD,
            "scenario": None, "node_id": None, "resource_id": None, "kind": None,
            "action": "request", "depth": None, "clue_from": None, "followed_clue": False,
            "limit_reached": False, "rabbit_hole_enabled": self.config.enabled,
        }
        response_headers = {"Content-Type": "text/html", "Server": self.server_header}
        if link != "cookie":
            response_headers["Set-Cookie"] = f"{SESSION_COOKIE}={sid}; Path=/; HttpOnly"
        status, payload = self._route(method, path, headers, body, state, faker, event,
                                      response_headers)
        event["status"] = status
        event["bytes"] = len(payload)
        if method == "HEAD":
            payload = b""
        return Response(status, response_headers, payload, event)

    def _page(self, template: str, headers: dict, status: int) -> tuple:
        headers["Content-Type"] = "text/html"
        return status, template.format(server=self.server_header).encode("utf-8")

    def _route(self, method, path, headers, body, state, faker, event, out) -> tuple:
        if method not in {"GET", "HEAD", "POST"}:
            return self._page(NOT_ALLOWED, out, 405)
        if len(body) > MAX_BODY:
            return self._page(TOO_LARGE, out, 413)
        if path == "/":
            event["action"] = "open_page"
            out["Content-Type"] = "text/html; charset=utf-8"
            return 200, self._landing().encode("utf-8")
        if not self.config.enabled:
            return self._page(NOT_FOUND, out, 404)
        match = self.routes.get(path)
        item_id = None
        if match is None and path + "/" in self.routes and self.routes[path + "/"][1].kind == "listing":
            out["Location"] = path + "/"
            return self._page(NOT_FOUND.replace("404 Not Found", "301 Moved Permanently"), out, 301)
        if match is None:
            for route, (scenario, node) in self.routes.items():
                if node.kind == "people_api" and path.startswith(route + "/"):
                    rest = path[len(route) + 1:].strip("/")
                    if rest.isdigit():
                        match, item_id = (scenario, node), int(rest)
                    break
        if match is None:
            if path in self.fillers:
                event["action"] = "read_file"
                return self._page(FORBIDDEN, out, 403)
            return self._page(NOT_FOUND, out, 404)
        scenario, node = match
        if node.depth > self.config.limits["max_depth"]:
            return self._page(NOT_FOUND, out, 404)
        resource = node.id if item_id is None else f"{node.id}/{item_id}"
        if (resource not in state.accessed and
                len(state.accessed) >= self.config.limits["max_resources_per_session"]):
            state.limit_reached = True
            event.update(limit_reached=True, scenario=scenario.id)
            return self._page(NOT_FOUND, out, 404)
        event.update(scenario=scenario.id, node_id=node.id, resource_id=resource,
                     kind=node.kind, depth=node.depth, action=ACTIONS[node.kind])
        if node.id in state.revealed:
            event["clue_from"] = state.revealed[node.id]
            event["followed_clue"] = True
        paths = scenario.node_paths()
        context = {"session": state.id}
        if node.requires_header:
            for name, template in node.requires_header.items():
                expected = render(template, faker, paths, context)
                supplied = headers.get(name.lower(), "")
                if supplied == expected:
                    continue
                owner = self._api_key_owner(supplied)
                if owner and owner != state.id:
                    event["linked_session"] = owner
                    event["link"] = "api_key"
                    continue
                out["Content-Type"] = "application/json"
                event["action"] = "call_api_denied"
                return 401, json.dumps({"error": f"missing or invalid {name}"}).encode()
        if node.kind == "form" and method == "POST":
            event["action"] = "submit_form"
            event["form_fields"] = sorted(k for k, _ in parse_qsl(body.decode("utf-8", "replace")))[:20]
            target = node.next[0] if node.next else None
            if target:
                state.revealed.setdefault(target, node.id)
                out["Location"] = paths[target]
                self._accessed(state, resource)
                return self._page(NOT_FOUND.replace("404 Not Found", "302 Found"), out, 302)
        content = self._content(scenario, node, faker, paths, context, item_id)
        if content is None:
            out["Content-Type"] = "application/json"
            return 404, b'{"error":"not found"}'
        self._accessed(state, resource)
        for child in node.next:
            state.revealed.setdefault(child, node.id)
        # Remember API keys handed out in this session so later calls can be linked.
        if "{{secret:token:api}}" in node.body:
            self._remember_key(faker.token("api"), state.id)
        out["Content-Type"] = node.content_type
        return node.status, content.encode("utf-8")

    @staticmethod
    def _accessed(state: SessionState, resource: str) -> None:
        if resource not in state.accessed:
            state.accessed.append(resource)

    def _content(self, scenario, node, faker, paths, context, item_id) -> str | None:
        if node.kind == "listing":
            return self._listing(scenario, node, faker, paths)
        if node.kind == "people_api":
            count = int(node.body or 10)
            people = faker.people(count)
            if item_id is None:
                return json.dumps({"items": [{k: p[k] for k in ("id", "name", "email", "role")}
                                             for p in people], "total": count}, indent=2)
            match = [p for p in people if p["id"] == item_id]
            return json.dumps(match[0], indent=2) if match else None
        return render(node.body, faker, paths, context)

    def _listing(self, scenario, node, faker, paths) -> str:
        entries = []
        for child_id in node.next:
            child = scenario.nodes[child_id]
            if not child.path.startswith(node.path) or child.path == node.path:
                continue
            name = child.path[len(node.path):]
            size = "-" if child.kind == "listing" else str(len(self._content(
                scenario, child, faker, paths, {}, None) or ""))
            entries.append((name, size))
        for name in node.filler:
            rendered = render(name, self.deployment, {})
            entries.append((rendered, str(faker.number("size:" + rendered, 40000, 9000000))))
        stamp = (faker.day(-faker.number("listing:" + node.id, 1, 20)))
        lines = ['<a href="../">../</a>']
        for name, size in sorted(entries):
            when = datetime.strptime(stamp, "%Y-%m-%d").strftime("%d-%b-%Y") + " 02:" + \
                str(faker.number("min:" + name, 10, 59))
            link = f'<a href="{escape(name, quote=True)}">{escape(name)}</a>'
            lines.append(link + " " * max(1, 51 - len(name)) + f"{when}{size:>20}")
        title = escape(node.path)
        return (f"<html>\r\n<head><title>Index of {title}</title></head>\r\n<body>\r\n"
                f"<h1>Index of {title}</h1><hr><pre>" + "\r\n".join(lines) +
                "\r\n</pre><hr></body>\r\n</html>\r\n")

    def _landing(self) -> str:
        org = self.config.organization
        name = escape(str(org.get("name")))
        return ("<!doctype html><html><head><meta charset=\"utf-8\"><title>" + name +
                "</title></head><body style=\"font-family:sans-serif;max-width:720px;margin:60px auto\">"
                "<h1>" + name + "</h1><p>Customer portal is under scheduled maintenance. "
                "Please try again later.</p><p style=\"color:#888\">&copy; " +
                str(datetime.now().year) + " " + escape(str(org.get("domain"))) + "</p></body></html>")


def _int(value) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _cookie(raw: str, name: str) -> str | None:
    for part in raw.split(";"):
        key, _, value = part.strip().partition("=")
        if key == name:
            return value.strip()
    return None


def _log_headers(headers: dict) -> dict:
    result = {}
    for key, value in list(headers.items())[:40]:
        if key in DROPPED_HEADERS:
            continue
        value = str(value)[:512]
        if key in MASKED_HEADERS:
            value = value[:6] + "…(" + str(len(value)) + " chars)" if value else value
        result[key] = value
    return result


class EventLog:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()

    def write(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(line)


def handler_factory(engine: WebEngine, log: EventLog):
    class Handler(BaseHTTPRequestHandler):
        server_version = engine.server_header
        sys_version = ""
        timeout = 15
        protocol_version = "HTTP/1.1"

        def _serve(self):
            length = self.headers.get("Content-Length") or "0"
            try:
                size = max(0, int(length))
            except ValueError:
                size = 0
            body = b""
            if size and size <= MAX_BODY:
                body = self.rfile.read(size)
            elif size > MAX_BODY:
                body = b"\0" * (MAX_BODY + 1)
            response = engine.handle(self.command, self.path, dict(self.headers.items()), body,
                                     self.client_address, self.server.server_address)
            try:
                log.write(response.event)
            except OSError:
                pass
            self.send_response(response.status)
            for key, value in response.headers.items():
                if key != "Server":
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(response.body)))
            if size > MAX_BODY:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(response.body)

        do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = _serve

        def version_string(self):
            return engine.server_header

        def log_message(self, format, *args):
            return

    return Handler


def serve(config: RabbitConfig) -> None:
    engine = WebEngine(config)
    log = EventLog(config.log_path)
    server = ThreadingHTTPServer((config.web["host"], int(config.web["port"])),
                                 handler_factory(engine, log))
    server.daemon_threads = True
    print(f"Rabbit Hole web decoy on http://{config.web['host']}:{config.web['port']}/ "
          f"log={config.log_path} scenarios={[s.id for s in engine.scenarios]}")
    server.serve_forever()


def new_session_id() -> str:
    return secrets.token_hex(16)
