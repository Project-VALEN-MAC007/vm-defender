from __future__ import annotations

import json
from pathlib import Path

from .adapters import NftSetAdapter, NginxMapAdapter
from .config import Settings
from .models import Event
from .reader import EveReader
from .risk import RiskEngine


def _nginx_validate(_: Path) -> bool:
    import subprocess
    return subprocess.run(["nginx", "-t"], capture_output=True, text=True).returncode == 0


def _nginx_reload() -> bool:
    import subprocess
    return subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True).returncode == 0


class DecisionEngine:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.reader = EveReader(settings.eve_path, settings.checkpoint_path)
        self.risk = RiskEngine(settings.thresholds, settings.decay_per_minute, settings.expiry_seconds)
        self.nft = NftSetAdapter(settings.nft_family, settings.nft_table, settings.dry_run)
        self.nginx = NginxMapAdapter(settings.nginx_map_path, settings.dry_run, None if settings.dry_run else _nginx_validate, None if settings.dry_run else _nginx_reload)
        self.web_entries: dict[str, str] = {}

    @staticmethod
    def _retry(operation, attempts: int = 3):
        last_error = None
        for _ in range(attempts):
            try:
                return operation()
            except Exception as exc:
                last_error = exc
        raise last_error

    def _audit(self, payload: dict) -> None:
        self.settings.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.settings.audit_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, sort_keys=True) + "\n")

    def run_once(self) -> list[dict]:
        decisions: list[dict] = []
        for raw in self.reader.records():
            if raw.get("event_type") != "alert":
                continue
            try:
                event = Event.from_eve(raw)
                decision = self.risk.decide(event)
                if decision is None:
                    continue
                payload = decision.as_dict()
                if decision.action == "redirect_web":
                    self.web_entries[decision.source_ip] = decision.profile
                    payload["adapter_result"] = self._retry(lambda: self.nginx.update(self.web_entries))
                elif decision.action == "redirect_ssh":
                    payload["adapter_command"] = self._retry(lambda: self.nft.add("ssh_redirect", decision.source_ip, self.settings.expiry_seconds))
                elif decision.action == "redirect_telnet":
                    payload["adapter_command"] = self._retry(lambda: self.nft.add("telnet_redirect", decision.source_ip, self.settings.expiry_seconds))
                elif decision.action == "temporary_block":
                    payload["adapter_command"] = self._retry(lambda: self.nft.add("temporary_block", decision.source_ip, self.settings.expiry_seconds))
                payload["dry_run"] = self.settings.dry_run
                self._audit(payload)
                decisions.append(payload)
            except Exception as exc:
                self._audit({"status": "error", "error": type(exc).__name__, "detail": str(exc), "dry_run": self.settings.dry_run})
        return decisions
