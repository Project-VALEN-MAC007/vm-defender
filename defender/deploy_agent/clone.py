"""Clone a website into SNARE's page format on the Defender.

The Honeypot is isolated (deploy/isolation): it may not open connections to the
real web server. So the Defender, which already proxies to the real web server,
fetches the pages and hands the finished copy to the deploy agent on the
Honeypot over the agent's authenticated API (POST /v1/versions).

The output matches SNARE's own cloner (snare/cloner.py): one file per URL named
by the MD5 of its path, plus meta.json mapping the path to that name and the
response headers. "/" is stored as "/index.html" and "/status_404" is fetched
for the not-found page. Absolute links to the cloned site are made relative.

Only the allowed host:port is ever fetched, including redirects, so the Dashboard
cannot be used to reach other internal machines (SSRF). Standard library only.
"""
from __future__ import annotations

import base64
import hashlib
from html.parser import HTMLParser
import json
import re
from typing import Callable
from urllib.error import HTTPError
from urllib.parse import urldefrag, urljoin, urlsplit
import urllib.request

IGNORED_HEADERS = {"age", "cache-control", "connection", "content-encoding", "content-length", "date",
                   "etag", "expires", "x-cache", "set-cookie", "transfer-encoding", "keep-alive"}
HASH_PATTERN = re.compile(r"^[0-9a-f]{32}$")
CSS_URL = re.compile(rb"""url\(\s*['"]?([^'")\s]+)['"]?\s*\)""")
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 40 * 1024 * 1024
MAX_PAGES = 500


def check_target(url: str, allowed: list) -> str:
    """Return the normalised URL or raise ValueError. Prevents cloning arbitrary hosts (SSRF)."""
    if not isinstance(url, str) or len(url) > 512:
        raise ValueError("invalid_url")
    parts = urlsplit(url.strip())
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("url_must_be_http_or_https")
    if parts.username or parts.password:
        raise ValueError("url_must_not_contain_credentials")
    host = parts.hostname.lower()
    hostport = f"{host}:{parts.port}" if parts.port else host
    if hostport not in allowed and host not in allowed:
        raise ValueError("target_not_allowed")
    return f"{parts.scheme}://{hostport}{parts.path or '/'}"


def file_name(url: str) -> tuple:
    parts = urlsplit(url)
    name = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    if name == "/":
        name = "/index.html"
    return name, hashlib.md5(name.encode("utf-8")).hexdigest()


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key in {"href", "src", "action"} and value:
                self.links.append(value.strip())


class _SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin: str):
        super().__init__()
        self.origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origin(urljoin(req.full_url, newurl)) != self.origin:
            return None  # off-site redirect: keep the 3xx response itself
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{parts.scheme}://{(parts.hostname or '').lower()}:{port}"


class SiteCloner:
    """Breadth-first copy of one site, limited by depth, page count and size."""

    def __init__(self, url: str, depth: int, log: list | None = None, fetch: Callable | None = None,
                 timeout: int = 10, max_pages: int = MAX_PAGES, max_bytes: int = MAX_TOTAL_BYTES):
        self.root = url
        self.origin = _origin(url)
        self.depth = depth
        self.log = log if log is not None else []
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_bytes = max_bytes
        self.fetch = fetch or self._fetch
        self._opener = urllib.request.build_opener(_SameOriginRedirect(self.origin))

    def _fetch(self, url: str) -> tuple:
        request = urllib.request.Request(url, headers={"Accept": "text/html,*/*", "User-Agent": "Mozilla/5.0"})
        try:
            response = self._opener.open(request, timeout=self.timeout)
        except HTTPError as error:  # 404 page and other statuses are cloned as served
            response = error
        with response:
            headers = list(response.headers.items())
            data = response.read(MAX_FILE_BYTES + 1)
        return response.status if hasattr(response, "status") else response.code, headers, data

    def _same_site(self, url: str) -> bool:
        return urlsplit(url).scheme in {"http", "https"} and _origin(url) == self.origin

    def _relative(self, data: bytes) -> bytes:
        parts = urlsplit(self.root)
        prefixes = {f"{parts.scheme}://{parts.netloc}", f"//{parts.netloc}"}
        if parts.port in {None, 80, 443}:
            prefixes |= {f"{parts.scheme}://{parts.hostname}", f"//{parts.hostname}"}
        for prefix in sorted(prefixes, key=len, reverse=True):
            data = re.sub(re.escape(prefix.encode()) + rb"(?=[/\"'\s>?#]|$)", b"", data)
        return data

    def run(self) -> tuple:
        error_page = urljoin(self.root, "/status_404")
        queue = [(self.root, 0), (error_page, 0)]
        seen: set = set()
        files: dict = {}
        meta: dict = {}
        total = 0
        while queue:
            url, level = queue.pop(0)
            url = urldefrag(url)[0]
            if url in seen or not self._same_site(url):
                continue
            seen.add(url)
            if len(meta) >= self.max_pages:
                self.log.append(f"stopped at {self.max_pages} pages")
                break
            name, digest = file_name(url)
            if name in meta:
                continue
            try:
                status, headers, data = self.fetch(url)
            except Exception as exc:  # unreachable page: skip it like SNARE does
                self.log.append(f"skip {name}: {exc.__class__.__name__}")
                continue
            if len(data) > MAX_FILE_BYTES:
                self.log.append(f"skip {name}: larger than {MAX_FILE_BYTES} bytes")
                continue
            content_type = next((v for k, v in headers if k.lower() == "content-type"), "")
            if level < self.depth:
                links = []
                if "text/html" in content_type:
                    parser = _Links()
                    parser.feed(data.decode("utf-8", "replace"))
                    links = parser.links
                elif "text/css" in content_type:
                    links = [m.decode("utf-8", "replace") for m in CSS_URL.findall(data)]
                for link in links:
                    if link.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
                        continue
                    target = urldefrag(urljoin(url, link))[0]
                    if self._same_site(target) and target not in seen:
                        queue.append((target, level + 1))
            if "text/html" in content_type:
                data = self._relative(data)
            total += len(data)
            if total > self.max_bytes:
                self.log.append(f"stopped: copy larger than {self.max_bytes} bytes")
                break
            files[digest] = data
            meta[name] = {"hash": digest,
                          "headers": [{k: v} for k, v in headers if k.lower() not in IGNORED_HEADERS]}
            self.log.append(f"cloned {name} ({status}, {len(data)} bytes)")
        if "/index.html" not in meta:
            raise RuntimeError("clone_produced_no_pages")
        files["meta.json"] = json.dumps(meta, ensure_ascii=False).encode("utf-8")
        return files, meta


def demo_files(url: str) -> dict:
    """Pages for the Windows demo (web_deploy.dry_run), so no real site is fetched."""
    host = urlsplit(url).hostname or "site"
    pages = {
        "/index.html": f"<!doctype html><html><head><title>{host}</title></head><body><h1>{host}</h1>"
                       "<p>Customer portal</p><a href=\"/login.html\">Sign in</a></body></html>",
        "/login.html": "<!doctype html><html><head><title>Sign in</title></head><body><form method=\"post\">"
                       "<input name=\"username\"><input name=\"password\" type=\"password\"><button>Sign in"
                       "</button></form></body></html>",
        "/about.html": "<!doctype html><html><body><h2>About us</h2><p>Office: 10.20.0.15</p></body></html>",
        "/status_404": "<!doctype html><html><body><h1>404 Not Found</h1></body></html>",
    }
    files, meta = {}, {}
    for name, body in pages.items():
        digest = hashlib.md5(name.encode()).hexdigest()
        files[digest] = body.encode("utf-8")
        meta[name] = {"hash": digest, "headers": [{"Content-Type": "text/html; charset=utf-8"}]}
    files["meta.json"] = json.dumps(meta).encode("utf-8")
    return files


def encode_package(url: str, depth: int, files: dict) -> dict:
    return {"url": url, "depth": depth,
            "files": {name: base64.b64encode(data).decode("ascii") for name, data in files.items()}}


def decode_package(payload: dict) -> tuple:
    """Validate an uploaded copy. Returns (url, depth, files). Raises ValueError."""
    if not isinstance(payload, dict) or not isinstance(payload.get("files"), dict):
        raise ValueError("invalid_package")
    url, depth = payload.get("url"), payload.get("depth")
    if not isinstance(url, str) or not urlsplit(url).hostname or len(url) > 512:
        raise ValueError("invalid_package_url")
    if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= 5:
        raise ValueError("depth_must_be_1_to_5")
    files, total = {}, 0
    for name, encoded in payload["files"].items():
        if name != "meta.json" and not (isinstance(name, str) and HASH_PATTERN.match(name)):
            raise ValueError("invalid_package_file_name")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid_package_encoding") from exc
        total += len(data)
        if len(data) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise ValueError("package_too_large")
        files[name] = data
    try:
        meta = json.loads(files.get("meta.json", b"").decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid_package_meta") from exc
    if not isinstance(meta, dict) or "/index.html" not in meta or len(meta) > MAX_PAGES:
        raise ValueError("invalid_package_meta")
    for name, item in meta.items():
        if (not isinstance(name, str) or not name.startswith("/") or not isinstance(item, dict)
                or not HASH_PATTERN.match(str(item.get("hash", ""))) or item["hash"] not in files):
            raise ValueError("invalid_package_meta")
    return url, depth, files
