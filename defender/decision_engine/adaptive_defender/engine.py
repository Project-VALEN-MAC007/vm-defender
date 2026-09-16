from __future__ import annotations

import json
import copy
from datetime import datetime, timezone
import os
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
        self.web_state_path = settings.nginx_map_path.with_suffix(settings.nginx_map_path.suffix + ".state.json")
        self.web_entries = self._load_web_entries()
        self._web_reconciled = False

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

    def _load_web_entries(self) -> dict[str, dict[str, str]]:
        if self.settings.dry_run or not self.web_state_path.exists():
            return {}
        try:
            raw = json.loads(self.web_state_path.read_text(encoding="utf-8"))
            return {str(address): value for address, value in raw.items()
                    if isinstance(value, dict) and value.get("profile") and value.get("expiry")}
        except (OSError, ValueError, json.JSONDecodeError):
            return {}

    def _save_web_entries(self) -> None:
        if self.settings.dry_run:
            return
        self.web_state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.web_state_path.with_suffix(self.web_state_path.suffix + ".tmp")
        temporary.write_text(json.dumps(self.web_entries, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, self.web_state_path)

    def _active_web_profiles(self, now: datetime | None = None) -> dict[str, str]:
        now = now or datetime.now(timezone.utc)
        active = {}
        for address, item in self.web_entries.items():
            try:
                expiry = datetime.fromisoformat(item["expiry"].replace("Z", "+00:00"))
            except (KeyError, TypeError, ValueError):
                continue
            if expiry > now:
                active[address] = item["profile"]
        return active

    def reconcile_web_redirects(self) -> None:
        active = self._active_web_profiles()
        if self._web_reconciled and len(active) == len(self.web_entries):
            return
        self.web_entries = {address: self.web_entries[address] for address in active}
        self._retry(lambda: self.nginx.update(active))
        self._save_web_entries()
        self._web_reconciled = True

    def _apply_web_redirect(self, decision) -> str:
        previous = copy.deepcopy(self.web_entries)
        self.web_entries[decision.source_ip] = {
            "profile": decision.profile,
            "expiry": decision.expiry,
        }
        try:
            result = self._retry(lambda: self.nginx.update(self._active_web_profiles()))
            self._save_web_entries()
            return result
        except Exception:
            self.web_entries = previous
            raise

    def run_once(self) -> list[dict]:
        decisions: list[dict] = []
        self.reconcile_web_redirects()
        for pending in self.reader.pending_records():
            raw = pending.record
            if raw.get("event_type") != "alert":
                self.reader.commit(pending)
                continue
            previous_states = copy.deepcopy(self.risk.states)
            previous_seen = copy.deepcopy(self.risk.seen)
            try:
                event = Event.from_eve(raw)
                decision = self.risk.decide(event)
                if decision is None:
                    self.reader.commit(pending)
                    continue
                payload = decision.as_dict()
                if decision.action == "redirect_web":
                    payload["adapter_result"] = self._apply_web_redirect(decision)
                elif decision.action == "redirect_ssh":
                    payload["adapter_command"] = self._retry(lambda: self.nft.add("ssh_redirect", decision.source_ip, self.settings.expiry_seconds))
                elif decision.action == "redirect_telnet":
                    payload["adapter_command"] = self._retry(lambda: self.nft.add("telnet_redirect", decision.source_ip, self.settings.expiry_seconds))
                elif decision.action == "temporary_block":
                    payload["adapter_command"] = self._retry(lambda: self.nft.add("temporary_block", decision.source_ip, self.settings.expiry_seconds))
                payload["dry_run"] = self.settings.dry_run
                self._audit(payload)
                self.reader.commit(pending)
                decisions.append(payload)
            except Exception as exc:
                self.risk.states = previous_states
                self.risk.seen = previous_seen
                self._audit({"status": "error", "error": type(exc).__name__, "detail": str(exc), "dry_run": self.settings.dry_run})
                break
        return decisions
