"""TRAP deploy agent: clone a website with SNARE and switch SNARE to it.

Runs on the Honeypot machine. Only the Defender dashboard may call it, with a
bearer token, from an allowed IP. Operations are fixed:

  GET  /v1/status                       current page dir, health, versions, running job
  POST /v1/clone      {url, depth}      clone an allowed URL into a new version
  POST /v1/activate   {version}         point SNARE at a version, recreate, health-check, roll back on failure
  GET  /v1/jobs/<id>                    job state and log
  GET  /v1/versions/<v>/pages           cloned URLs of a version
  GET  /v1/versions/<v>/page?url=/x     one cloned page (for the dashboard preview)

Commands are built from fixed argv lists; nothing from a request reaches a shell.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import threading
import time
from typing import Callable
from urllib.parse import parse_qs, urlsplit
import urllib.request

VERSION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{0,90}$")
MAX_LOG_LINES = 400
MAX_PAGE_BYTES = 512 * 1024
SCAN_RULES = [
    ("secret", re.compile(rb"(?i)(password|passwd|secret|api[_-]?key|access[_-]?token)[\"']?\s*[:=]\s*[\"'][^\"'\s]{6,}")),
    ("private_key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("internal_ip", re.compile(rb"\b(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")),
]
SCAN_LABELS = {"secret": "รหัสผ่านหรือ key", "private_key": "private key", "aws_key": "AWS Access Key",
               "internal_ip": "IP ภายใน", "source_map": "ไฟล์ source map (เปิดเผยโค้ดต้นฉบับ)"}


@dataclass
class AgentConfig:
    bind_host: str
    bind_port: int
    token: str
    allowed_clients: list
    allowed_targets: list
    compose_dir: Path
    env_file: Path
    data_dir: Path
    health_url: str
    docker: str = "docker"
    run_as: str = ""
    keep_versions: int = 10
    clone_timeout: int = 900
    dry_run: bool = False


def load_config(path: str | Path) -> AgentConfig:
    path = Path(path).resolve()
    raw = json.loads(path.read_text(encoding="utf-8"))
    base = path.parent

    def resolve(value: str) -> Path:
        candidate = Path(value)
        return candidate if candidate.is_absolute() else (base / candidate).resolve()

    token_file = resolve(raw["token_file"])
    token = token_file.read_text(encoding="utf-8").strip()
    if len(token) < 32:
        raise ValueError("token must be at least 32 characters")
    clients = [ipaddress.ip_network(c, strict=False) for c in raw.get("allowed_clients") or []]
    if not clients:
        raise ValueError("allowed_clients must not be empty")
    targets = [str(t).lower().strip() for t in raw.get("allowed_targets") or []]
    if not targets:
        raise ValueError("allowed_targets must not be empty")
    compose_dir = resolve(raw["compose_dir"])
    return AgentConfig(
        bind_host=str(raw.get("bind_host", "127.0.0.1")), bind_port=int(raw.get("bind_port", 8091)),
        token=token, allowed_clients=clients, allowed_targets=targets, compose_dir=compose_dir,
        env_file=resolve(raw.get("env_file", str(compose_dir / "settings.env"))),
        data_dir=resolve(raw.get("data_dir", str(compose_dir / "data/snare"))),
        health_url=str(raw.get("health_url", "http://127.0.0.1:8083/")),
        docker=str(raw.get("docker", "docker")), run_as=str(raw.get("run_as", "")),
        keep_versions=max(2, int(raw.get("keep_versions", 10))),
        clone_timeout=int(raw.get("clone_timeout", 900)), dry_run=raw.get("dry_run") is True)


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


def scan_version(folder: Path) -> list:
    """Look for things that should not be published in a decoy copy."""
    meta = _meta(folder)
    names = {item.get("hash"): url for url, item in meta.items() if isinstance(item, dict)}
    findings = []
    for url in meta:
        if url.endswith(".map"):
            findings.append({"rule": "source_map", "label": SCAN_LABELS["source_map"], "url": url})
    for path in sorted(folder.iterdir()):
        if not path.is_file() or path.name == "meta.json" or path.stat().st_size > 4 * MAX_PAGE_BYTES:
            continue
        data = path.read_bytes()
        for rule, pattern in SCAN_RULES:
            match = pattern.search(data)
            if match:
                findings.append({"rule": rule, "label": SCAN_LABELS[rule], "url": names.get(path.name, path.name),
                                 "sample": match.group(0)[:60].decode("utf-8", "replace")})
        if len(findings) >= 50:
            break
    return findings


def _meta(folder: Path) -> dict:
    try:
        value = json.loads((folder / "meta.json").read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def read_env(path: Path) -> dict:
    values = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip()
    return values


def write_env_value(path: Path, key: str, value: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    out, done = [], False
    for line in lines:
        if line.split("=", 1)[0].strip() == key and not line.lstrip().startswith("#"):
            out.append(f"{key}={value}")
            done = True
        else:
            out.append(line)
    if not done:
        out.append(f"{key}={value}")
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text("\n".join(out) + "\n", encoding="utf-8")
    os.replace(temporary, path)


@dataclass
class Job:
    id: str
    kind: str
    status: str = "queued"
    started: str | None = None
    finished: str | None = None
    log: list = field(default_factory=list)
    result: dict = field(default_factory=dict)
    error: str | None = None

    def public(self) -> dict:
        return {"id": self.id, "kind": self.kind, "status": self.status, "started": self.started,
                "finished": self.finished, "log": self.log[-MAX_LOG_LINES:], "result": self.result,
                "error": self.error}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Agent:
    def __init__(self, config: AgentConfig, runner: Callable | None = None,
                 health: Callable[[], bool] | None = None):
        self.config = config
        self.runner = runner or (self._dry_runner if config.dry_run else self._run)
        self.health = health or (lambda: True if config.dry_run else self._health())
        self.lock = threading.Lock()
        self.jobs: dict = {}
        self.current: Job | None = None
        self.pages = config.data_dir / "pages"
        self.pages.mkdir(parents=True, exist_ok=True)
        self.registry = config.data_dir / "trap-versions.json"

    # ---------- registry ----------
    def versions(self) -> dict:
        try:
            data = json.loads(self.registry.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_versions(self, data: dict) -> None:
        temporary = self.registry.with_name(self.registry.name + ".tmp")
        temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, self.registry)

    def active(self) -> str:
        return read_env(self.config.env_file).get("SNARE_PAGE_DIR", "demo")

    def status(self) -> dict:
        versions = self.versions()
        active = self.active()
        items = sorted(versions.values(), key=lambda v: v.get("created", ""), reverse=True)
        for item in items:
            item["active"] = item["version"] == active
        return {"active": active, "healthy": bool(self.health()), "dry_run": self.config.dry_run,
                "allowed_targets": self.config.allowed_targets, "versions": items,
                "job": self.current.public() if self.current and self.current.status in {"queued", "running"} else None}

    # ---------- jobs ----------
    def _start(self, kind: str, work: Callable[[Job], dict]) -> Job:
        with self.lock:
            if self.current and self.current.status in {"queued", "running"}:
                raise RuntimeError("job_running")
            job = Job(id=secrets.token_hex(6), kind=kind)
            self.jobs[job.id] = job
            self.current = job
            while len(self.jobs) > 50:
                self.jobs.pop(next(iter(self.jobs)))

        def target():
            job.status, job.started = "running", _now()
            try:
                job.result = work(job)
                job.status = "succeeded"
            except Exception as exc:  # report every failure to the dashboard
                job.status, job.error = "failed", str(exc)[:500]
                job.log.append("ERROR: " + job.error)
            job.finished = _now()

        threading.Thread(target=target, daemon=True).start()
        return job

    def clone(self, url: str, depth) -> Job:
        target = check_target(url, self.config.allowed_targets)
        if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= 5:
            raise ValueError("depth_must_be_1_to_5")
        return self._start("clone", lambda job: self._clone(job, target, depth))

    def activate(self, version: str) -> Job:
        if version != "demo" and (not isinstance(version, str) or not VERSION_PATTERN.match(version)
                                  or version not in self.versions()):
            raise ValueError("unknown_version")
        return self._start("activate", lambda job: self._activate(job, version))

    def _compose(self, *args: str) -> list:
        base = [self.config.docker, "compose", "--project-directory", str(self.config.compose_dir),
                "--env-file", str(self.config.env_file)]
        return base + list(args)

    def _clone(self, job: Job, url: str, depth: int) -> dict:
        staging = self.config.data_dir / "staging" / job.id
        (staging / "snare").mkdir(parents=True, exist_ok=True)
        container_path = f"/opt/snare/staging/{job.id}/"
        argv = self._compose("--profile", "tools", "run", "--rm")
        if self.config.run_as:
            argv += ["--user", self.config.run_as]
        argv += ["clone", "--target", url, "--max-depth", str(depth), "--path", container_path]
        job.log.append(f"clone {url} depth={depth}")
        code = self.runner(argv, self.config.clone_timeout, job.log, staging=staging, url=url)
        if code != 0:
            raise RuntimeError(f"clone_failed (exit {code})")
        produced = [p for p in (staging / "snare" / "pages").glob("*") if p.is_dir()]
        if len(produced) != 1 or not (produced[0] / "meta.json").is_file():
            raise RuntimeError("clone_produced_no_pages")
        host = re.sub(r"[^a-z0-9.-]", "-", (urlsplit(url).hostname or "site").lower())[:60]
        version = f"{host}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        destination = self.pages / version
        shutil.move(str(produced[0]), str(destination))
        shutil.rmtree(staging, ignore_errors=True)
        meta = _meta(destination)
        size = sum(p.stat().st_size for p in destination.iterdir() if p.is_file())
        findings = scan_version(destination)
        record = {"version": version, "url": url, "depth": depth, "created": _now(),
                  "pages": len(meta), "bytes": size, "findings": findings, "job": job.id}
        versions = self.versions()
        versions[version] = record
        self._prune(versions)
        self._save_versions(versions)
        job.log.append(f"saved version {version}: {len(meta)} pages, {size} bytes, {len(findings)} findings")
        return record

    def _prune(self, versions: dict) -> None:
        active = self.active()
        ordered = sorted(versions.values(), key=lambda v: v.get("created", ""), reverse=True)
        for item in ordered[self.config.keep_versions:]:
            if item["version"] == active:
                continue
            shutil.rmtree(self.pages / item["version"], ignore_errors=True)
            versions.pop(item["version"], None)

    def _activate(self, job: Job, version: str) -> dict:
        previous = self.active()
        job.log.append(f"switch SNARE_PAGE_DIR {previous} -> {version}")
        write_env_value(self.config.env_file, "SNARE_PAGE_DIR", version)
        argv = self._compose("up", "-d", "--force-recreate", "--no-deps", "snare")
        healthy = self.runner(argv, 300, job.log) == 0 and self._wait_healthy(job)
        if healthy:
            job.log.append("SNARE is serving the new version")
            return {"active": version, "previous": previous, "rolled_back": False}
        job.log.append(f"health check failed; rolling back to {previous}")
        write_env_value(self.config.env_file, "SNARE_PAGE_DIR", previous)
        self.runner(argv, 300, job.log)
        self._wait_healthy(job)
        raise RuntimeError(f"activation_failed_rolled_back_to:{previous}")

    def _wait_healthy(self, job: Job, seconds: int = 60) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.health():
                return True
            time.sleep(0 if self.config.dry_run else 3)
        return False

    # ---------- preview ----------
    def _version_dir(self, version: str) -> Path:
        if not isinstance(version, str) or not VERSION_PATTERN.match(version):
            raise ValueError("unknown_version")
        folder = self.pages / version
        if not folder.is_dir():
            raise ValueError("unknown_version")
        return folder

    def page_list(self, version: str) -> list:
        meta = _meta(self._version_dir(version))
        return sorted(meta)[:500]

    def page(self, version: str, url: str) -> tuple:
        folder = self._version_dir(version)
        item = _meta(folder).get(url)
        if not isinstance(item, dict) or not re.fullmatch(r"[0-9a-f]{32}", str(item.get("hash", ""))):
            raise ValueError("page_not_found")
        path = folder / item["hash"]
        data = path.read_bytes()[:MAX_PAGE_BYTES] if path.is_file() else b""
        content_type = "text/html"
        for header in item.get("headers") or []:
            if isinstance(header, dict) and "Content-Type" in header:
                content_type = str(header["Content-Type"])
        return content_type, data

    # ---------- process runners ----------
    @staticmethod
    def _run(argv: list, timeout: int, log: list, **_) -> int:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.monotonic() + timeout
        assert process.stdout is not None
        for line in process.stdout:
            log.append(line.rstrip()[:300])
            del log[:-MAX_LOG_LINES]
            if time.monotonic() > deadline:
                process.kill()
                log.append("timeout")
                return 124
        return process.wait()

    @staticmethod
    def _dry_runner(argv: list, timeout: int, log: list, staging: Path | None = None, url: str = "", **_) -> int:
        """Simulates SNARE so the dashboard can be demonstrated without Docker."""
        log.append("[dry-run] " + " ".join(argv))
        if staging is None:
            log.append("[dry-run] snare recreated")
            return 0
        host = urlsplit(url).hostname or "site"
        folder = staging / "snare" / "pages" / host
        folder.mkdir(parents=True, exist_ok=True)
        pages = {
            "/index.html": f"<!doctype html><html><head><title>{host}</title></head><body><h1>{host}</h1>"
                           "<p>Customer portal</p><a href=\"/login.html\">Sign in</a></body></html>",
            "/login.html": "<!doctype html><html><head><title>Sign in</title></head><body><form method=\"post\">"
                           "<input name=\"username\"><input name=\"password\" type=\"password\"><button>Sign in"
                           "</button></form></body></html>",
            "/about.html": "<!doctype html><html><body><h2>About us</h2><p>Office: 10.20.0.15</p></body></html>",
            "/status_404": "<!doctype html><html><body><h1>404 Not Found</h1></body></html>",
        }
        meta = {}
        for page_url, body in pages.items():
            name = hashlib.md5(page_url.encode()).hexdigest()
            (folder / name).write_text(body, encoding="utf-8")
            meta[page_url] = {"hash": name, "headers": [{"Content-Type": "text/html; charset=utf-8"}]}
            log.append(f"[dry-run] cloned {page_url}")
            time.sleep(0.3)
        (folder / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
        return 0

    def _health(self) -> bool:
        try:
            with urllib.request.urlopen(self.config.health_url, timeout=4) as response:
                return 200 <= response.status < 500
        except Exception:
            return False


def handler_factory(agent: Agent):
    config = agent.config

    class Handler(BaseHTTPRequestHandler):
        server_version = "TRAPDeployAgent/1.0"
        sys_version = ""

        def _authorised(self) -> bool:
            try:
                peer = ipaddress.ip_address(self.client_address[0])
            except ValueError:
                peer = None
            supplied = self.headers.get("Authorization", "")
            ok = (peer is not None and any(peer in net for net in config.allowed_clients)
                  and hmac.compare_digest(supplied.encode(), ("Bearer " + config.token).encode()))
            if not ok:
                self._json({"error": "unauthorised"}, 401)
            return ok

        def _json(self, payload, status=200):
            body = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 16384:
                return {}
            try:
                value = json.loads(self.rfile.read(length))
                return value if isinstance(value, dict) else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {}

        def do_GET(self):
            if not self._authorised():
                return
            parts = urlsplit(self.path)
            segments = [s for s in parts.path.split("/") if s]
            try:
                if parts.path == "/v1/status":
                    self._json(agent.status())
                elif len(segments) == 3 and segments[:2] == ["v1", "jobs"]:
                    job = agent.jobs.get(segments[2])
                    self._json(job.public() if job else {"error": "job_not_found"}, 200 if job else 404)
                elif len(segments) == 4 and segments[:2] == ["v1", "versions"] and segments[3] == "pages":
                    self._json({"items": agent.page_list(segments[2])})
                elif len(segments) == 4 and segments[:2] == ["v1", "versions"] and segments[3] == "page":
                    url = (parse_qs(parts.query).get("url") or ["/index.html"])[0]
                    content_type, data = agent.page(segments[2], url)
                    self._json({"url": url, "content_type": content_type,
                                "content": data.decode("utf-8", "replace")})
                else:
                    self._json({"error": "not_found"}, 404)
            except ValueError as exc:
                self._json({"error": str(exc)}, 400)

        def do_POST(self):
            if not self._authorised():
                return
            payload = self._body()
            try:
                if self.path == "/v1/clone":
                    job = agent.clone(payload.get("url"), payload.get("depth"))
                elif self.path == "/v1/activate":
                    job = agent.activate(payload.get("version"))
                else:
                    self._json({"error": "not_found"}, 404)
                    return
            except ValueError as exc:
                self._json({"error": str(exc)}, 400)
                return
            except RuntimeError as exc:
                self._json({"error": str(exc)}, 409)
                return
            self._json(job.public(), 202)

        def log_message(self, format, *args):
            return

    return Handler


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="TRAP deploy agent for SNARE")
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    config = load_config(args.config)
    agent = Agent(config)
    server = ThreadingHTTPServer((config.bind_host, config.bind_port), handler_factory(agent))
    server.daemon_threads = True
    mode = " (dry-run, Docker is not called)" if config.dry_run else ""
    print(f"TRAP deploy agent on http://{config.bind_host}:{config.bind_port}{mode}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
