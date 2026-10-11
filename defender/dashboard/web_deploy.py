"""Web page deploy for the Honeypot's SNARE, driven from the Dashboard.

The Defender clones the real website itself (CloneJobs, using
defender/deploy_agent/clone.py) and uploads the copy to the deploy agent on the
Honeypot (DeployClient.upload). The Honeypot is isolated and never connects to
the real website. Switching SNARE to a version is still done by the agent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import threading
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
import urllib.request


class AgentError(Exception):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


class DeployClient:
    def __init__(self, agent_url: str | None, token_file: Path | None, timeout: int = 10):
        self.agent_url = (agent_url or "").rstrip("/")
        self.token_file = token_file
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.agent_url and self.token_file)

    def _token(self) -> str:
        try:
            token = self.token_file.read_text(encoding="utf-8").strip() if self.token_file else ""
        except OSError as exc:
            raise AgentError("deploy_agent_token_missing", 503) from exc
        if len(token) < 32:
            raise AgentError("deploy_agent_token_missing", 503)
        return token

    def _call(self, method: str, path: str, payload: dict | None = None, timeout: int | None = None) -> dict:
        if not self.available:
            raise AgentError("deploy_agent_not_configured", 404)
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(self.agent_url + path, data=body, method=method, headers={
            "Authorization": "Bearer " + self._token(), "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                return json.loads(response.read().decode("utf-8") or "{}")
        except HTTPError as exc:
            try:
                detail = json.loads(exc.read().decode("utf-8")).get("error", "agent_error")
            except (ValueError, OSError):
                detail = "agent_error"
            raise AgentError(detail, exc.code if exc.code in {400, 401, 404, 409, 413} else 502) from exc
        except (URLError, OSError, ValueError) as exc:
            raise AgentError("deploy_agent_unreachable", 502) from exc

    def status(self) -> dict:
        return self._call("GET", "/v1/status")

    def upload(self, package: dict) -> dict:
        return self._call("POST", "/v1/versions", package, timeout=120)

    def activate(self, version: str) -> dict:
        return self._call("POST", "/v1/activate", {"version": version})

    def job(self, job_id: str) -> dict:
        return self._call("GET", "/v1/jobs/" + quote(job_id, safe=""))

    def pages(self, version: str) -> dict:
        return self._call("GET", f"/v1/versions/{quote(version, safe='')}/pages")

    def page(self, version: str, url: str) -> dict:
        return self._call("GET", f"/v1/versions/{quote(version, safe='')}/page?" + urlencode({"url": url}))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CloneJob:
    id: str
    kind: str = "clone"
    status: str = "queued"
    started: str | None = None
    finished: str | None = None
    log: list = field(default_factory=list)
    result: dict = field(default_factory=dict)
    error: str | None = None

    def public(self) -> dict:
        return {"id": self.id, "kind": self.kind, "status": self.status, "started": self.started,
                "finished": self.finished, "log": self.log[-400:], "result": self.result, "error": self.error}


class CloneJobs:
    """Clone on the Defender in a background thread, then upload to the agent."""

    def __init__(self, client: DeployClient, allowed_targets: list, dry_run: bool = False,
                 cloner_factory=None):
        from defender.deploy_agent.clone import SiteCloner
        self.client = client
        self.allowed_targets = [str(t).lower().strip() for t in allowed_targets or []]
        self.dry_run = dry_run
        self.cloner_factory = cloner_factory or SiteCloner
        self.lock = threading.Lock()
        self.jobs: dict = {}
        self.current: CloneJob | None = None

    def running(self) -> dict | None:
        job = self.current
        return job.public() if job and job.status in {"queued", "running"} else None

    def start(self, url: str, depth) -> dict:
        from defender.deploy_agent.clone import check_target
        if not self.client.available:
            raise AgentError("deploy_agent_not_configured", 404)
        try:
            target = check_target(url, self.allowed_targets)
        except ValueError as exc:
            raise AgentError(str(exc), 400) from exc
        if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= 5:
            raise AgentError("depth_must_be_1_to_5", 400)
        with self.lock:
            if self.current and self.current.status in {"queued", "running"}:
                raise AgentError("job_running", 409)
            job = CloneJob(id="c" + secrets.token_hex(6))
            self.jobs[job.id] = job
            self.current = job
            while len(self.jobs) > 50:
                self.jobs.pop(next(iter(self.jobs)))
        threading.Thread(target=self._run, args=(job, target, depth), daemon=True).start()
        return job.public()

    def _run(self, job: CloneJob, url: str, depth: int) -> None:
        from defender.deploy_agent.clone import demo_files, encode_package
        job.status, job.started = "running", _now()
        try:
            job.log.append(f"Defender clones {url} depth={depth}")
            if self.dry_run:
                files = demo_files(url)
                job.log.append(f"[dry-run] {len(files) - 1} demo pages, no request sent")
            else:
                files, _ = self.cloner_factory(url, depth, log=job.log).run()
            job.log.append(f"upload {len(files) - 1} files to the Honeypot deploy agent")
            job.result = self.client.upload(encode_package(url, depth, files))
            job.log.append(f"saved version {job.result.get('version')}: {job.result.get('pages')} pages, "
                           f"{len(job.result.get('findings') or [])} findings")
            job.status = "succeeded"
        except Exception as exc:  # report every failure to the dashboard
            job.status, job.error = "failed", str(exc)[:500]
            job.log.append("ERROR: " + job.error)
        job.finished = _now()

    def get(self, job_id: str) -> dict | None:
        job = self.jobs.get(job_id)
        return job.public() if job else None
