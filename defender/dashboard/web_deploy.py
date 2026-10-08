"""Dashboard client for the deploy agent on the Honeypot machine."""
from __future__ import annotations

import json
from pathlib import Path
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

    def _call(self, method: str, path: str, payload: dict | None = None) -> dict:
        if not self.available:
            raise AgentError("deploy_agent_not_configured", 404)
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(self.agent_url + path, data=body, method=method, headers={
            "Authorization": "Bearer " + self._token(), "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8") or "{}")
        except HTTPError as exc:
            try:
                detail = json.loads(exc.read().decode("utf-8")).get("error", "agent_error")
            except (ValueError, OSError):
                detail = "agent_error"
            raise AgentError(detail, exc.code if exc.code in {400, 401, 404, 409} else 502) from exc
        except (URLError, OSError, ValueError) as exc:
            raise AgentError("deploy_agent_unreachable", 502) from exc

    def status(self) -> dict:
        return self._call("GET", "/v1/status")

    def clone(self, url: str, depth: int) -> dict:
        return self._call("POST", "/v1/clone", {"url": url, "depth": depth})

    def activate(self, version: str) -> dict:
        return self._call("POST", "/v1/activate", {"version": version})

    def job(self, job_id: str) -> dict:
        return self._call("GET", "/v1/jobs/" + quote(job_id, safe=""))

    def pages(self, version: str) -> dict:
        return self._call("GET", f"/v1/versions/{quote(version, safe='')}/pages")

    def page(self, version: str, url: str) -> dict:
        return self._call("GET", f"/v1/versions/{quote(version, safe='')}/page?" + urlencode({"url": url}))
