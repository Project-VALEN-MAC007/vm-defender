from __future__ import annotations

import json
import copy
from datetime import datetime, timezone
import os
import sys
from pathlib import Path

from .adapters import NftSetAdapter, NginxMapAdapter
from .config import Settings, load_settings
from .models import Event
from .reader import EveReader
from .risk import RiskEngine


def _nginx_validate(_: Path) -> bool:
    import subprocess
    return subprocess.run(["nginx", "-t"], capture_output=True, text=True).returncode == 0


class NginxReloader:
    """Reload nginx and wait until the new map is the one serving requests.

    `systemctl reload nginx` only signals the master. Until the master has
    started new workers and told the old ones to stop accepting, a request can
    still be served with the previous map (seen in the 2026-10-10 HTTPS retest:
    the first request after a redirect decision reached the real site). Ready
    means: at least one worker that did not exist before the reload, and every
    old worker gone or titled "worker process is shutting down" (old workers
    close their listening sockets when they take that title).

    `last_ready` is True when confirmed, False on timeout, None when it could
    not be checked (no pid file). A timeout does not fail the reload: the map
    is valid and nginx was signalled; the decision records the outcome.
    """

    def __init__(self, pid_file: Path = Path("/run/nginx.pid"), proc_root: Path = Path("/proc"),
                 timeout: float = 5.0, interval: float = 0.05, run=None, sleep=None, monotonic=None):
        import subprocess
        import time
        self.pid_file, self.proc_root = Path(pid_file), Path(proc_root)
        self.timeout, self.interval = timeout, interval
        self.run = run or (lambda command: subprocess.run(command, capture_output=True, text=True))
        self.sleep = sleep or time.sleep
        self.monotonic = monotonic or time.monotonic
        self.last_ready: bool | None = None
        self.last_wait_seconds: float | None = None

    def _master(self) -> int | None:
        try:
            return int(self.pid_file.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return None

    def _workers(self, master: int) -> dict[int, str]:
        workers: dict[int, str] = {}
        try:
            entries = list(self.proc_root.iterdir())
        except OSError:
            return workers
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
                parent = int(stat.rsplit(")", 1)[1].split()[1])
                if parent != master:
                    continue
                title = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
            except (OSError, ValueError, IndexError):
                continue  # process exited while we looked
            if "worker process" in title:
                workers[int(entry.name)] = title
        return workers

    def __call__(self) -> bool:
        master = self._master()
        before = set(self._workers(master)) if master is not None else set()
        started = self.monotonic()
        if self.run(["systemctl", "reload", "nginx"]).returncode != 0:
            self.last_ready, self.last_wait_seconds = False, None
            return False
        if master is None:
            self.last_ready, self.last_wait_seconds = None, None
            return True
        deadline = started + self.timeout
        while True:
            current = self._workers(master)
            fresh = [pid for pid in current if pid not in before]
            still_serving = [pid for pid, title in current.items()
                             if pid in before and "shutting down" not in title]
            now = self.monotonic()
            if fresh and not still_serving:
                self.last_ready, self.last_wait_seconds = True, round(now - started, 3)
                return True
            if now >= deadline:
                self.last_ready, self.last_wait_seconds = False, round(now - started, 3)
                return True
            self.sleep(self.interval)


class DecisionEngine:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.reader = EveReader(settings.eve_path, settings.checkpoint_path)
        self.risk = RiskEngine(settings.thresholds, settings.decay_per_minute, settings.expiry_seconds,
                               web_profile=settings.web_profile,
                               scan_only_signatures=settings.scan_only_signatures)
        self.nft = NftSetAdapter(settings.nft_family, settings.nft_table, settings.dry_run)
        self.nginx_reloader = None if settings.dry_run else NginxReloader()
        self.nginx = NginxMapAdapter(settings.nginx_map_path, settings.dry_run,
                                     None if settings.dry_run else _nginx_validate, self.nginx_reloader)
        self.web_state_path = settings.nginx_map_path.with_suffix(settings.nginx_map_path.suffix + ".state.json")
        self.web_entries = self._load_web_entries()
        self._web_reconciled = False
        # Adapter failures on one record, keyed by its position in eve.json.
        self._failures: dict[tuple[int, int], int] = {}

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

    MAX_ADAPTER_ATTEMPTS = 3

    def _skip(self, pending, reason: str, detail: str) -> None:
        """Record why an alert was not acted on and move past it."""
        self._audit({"status": "skipped", "reason": reason, "detail": detail[:500],
                     "event_offset": pending.offset, "dry_run": self.settings.dry_run})
        self.reader.commit(pending)

    def _apply(self, decision) -> dict:
        payload = decision.as_dict()
        address_v6 = ":" in decision.source_ip
        action = decision.action
        if address_v6 and action in {"redirect_ssh", "redirect_telnet"}:
            # IPv4 DNAT cannot reach Cowrie for an IPv6 client; monitor instead.
            payload["action"] = action = "monitor"
            payload["profile"] = "real"
            payload["reason"] = (payload.get("reason") or "") + ";ipv6_shell_redirect_unsupported:monitor"
        if action == "redirect_web":
            payload["adapter_result"] = self._apply_web_redirect(decision)
            if self.nginx_reloader is not None:
                # Written after nginx confirmed the new map, so a logged
                # redirect_web means requests from this source now reach the honeypot.
                payload["nginx_ready"] = self.nginx_reloader.last_ready
                payload["nginx_ready_seconds"] = self.nginx_reloader.last_wait_seconds
        elif action == "redirect_ssh":
            payload["adapter_command"] = self._retry(lambda: self.nft.add("ssh_redirect", decision.source_ip, self.settings.expiry_seconds))
        elif action == "redirect_telnet":
            payload["adapter_command"] = self._retry(lambda: self.nft.add("telnet_redirect", decision.source_ip, self.settings.expiry_seconds))
        payload["dry_run"] = self.settings.dry_run
        return payload

    def run_once(self) -> list[dict]:
        if self.settings.config_path:
            # Reload only thresholds; preserve accumulated risk and adapter state.
            # A bad edit must not stop redirects: keep the last good thresholds.
            try:
                self.risk.thresholds = load_settings(self.settings.config_path).thresholds
            except (OSError, ValueError, TypeError) as exc:
                if getattr(self, "_threshold_error", None) != str(exc):
                    self._threshold_error = str(exc)
                    # journald via stderr; decisions.jsonl stays decisions only.
                    print(json.dumps({"event": "threshold_reload_failed",
                                      "detail": f"{type(exc).__name__}: {exc}",
                                      "kept": dict(self.risk.thresholds)}), file=sys.stderr, flush=True)
            else:
                self._threshold_error = None
        decisions: list[dict] = []
        self.reconcile_web_redirects()
        for pending in self.reader.pending_records():
            raw = pending.record
            if raw.get("event_type") != "alert":
                self.reader.commit(pending)
                continue
            try:
                event = Event.from_eve(raw)
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                # A record we cannot read will never become readable; skipping it
                # keeps one odd alert from stopping every later redirect.
                self._skip(pending, "unreadable_alert", f"{type(exc).__name__}: {exc}")
                continue
            previous_states = copy.deepcopy(self.risk.states)
            previous_seen = copy.deepcopy(self.risk.seen)
            key = (pending.inode, pending.offset)
            try:
                decision = self.risk.decide(event)
                if decision is None:
                    self.reader.commit(pending)
                    continue
                payload = self._apply(decision)
                self._audit(payload)
                self.reader.commit(pending)
                self._failures.pop(key, None)
                decisions.append(payload)
            except Exception as exc:
                self.risk.states = previous_states
                self.risk.seen = previous_seen
                attempts = self._failures.get(key, 0) + 1
                self._audit({"status": "error", "error": type(exc).__name__, "detail": str(exc),
                             "attempt": attempts, "dry_run": self.settings.dry_run})
                if attempts >= self.MAX_ADAPTER_ATTEMPTS:
                    # Give up on this record only; later alerts still get processed.
                    self._failures.pop(key, None)
                    self._skip(pending, "adapter_failed", f"{type(exc).__name__}: {exc}")
                    continue
                self._failures[key] = attempts
                break
        return decisions
