from __future__ import annotations

import csv
from dataclasses import dataclass
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import parse_qs, urlparse

from .config import DashboardSettings
from .data_store import JsonlTail, alert_transform, decision_transform
from .metrics import calculate
from .security import LoginLimiter, Session, SessionStore, UserStore, append_security_audit
from ..validation.deploy import staged_deploy
from ..validation.pipeline import ValidationError, validate


FIELDS = ["start_time", "source_ip", "protocol", "signature_id", "severity",
          "risk_score", "action", "profile", "reason", "expiry"]
ALERT_FIELDS = ["timestamp", "src_ip", "src_port", "dest_ip", "dest_port",
                "proto", "app_proto", "signature_id", "signature", "category",
                "severity", "http_url", "http_user_agent"]
DEFAULT_EVE_PATHS = ("/var/log/suricata/eve.json", "evidence/test-results/eve.json",
                     "evidence/test-results/http-positive-run1/eve.json",
                     "evidence/test-results/http-benign-run1/eve.json")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
RULES_PATH = PROJECT_ROOT / "defender/suricata/rules/local.rules"
BASELINE_PATH = PROJECT_ROOT / "tests/fixtures/baseline.json"


def read_alerts(paths, limit: int = 500) -> list[dict]:
    rows = []
    for candidate in paths:
        path = Path(candidate)
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                row = alert_transform(json.loads(line), path)
            except json.JSONDecodeError:
                continue
            if row is not None:
                rows.append(row)
    rows.sort(key=lambda row: row.get("timestamp") or "", reverse=True)
    return rows[:limit]


def read_decisions(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        try:
            item = decision_transform(json.loads(line), path)
        except json.JSONDecodeError:
            continue
        if item is not None:
            rows.append(item)
    return rows


def summary(rows: list[dict]) -> dict:
    by_action: dict[str, int] = {}
    by_protocol: dict[str, int] = {}
    for row in rows:
        action = row.get("action", "unknown")
        protocol = row.get("protocol", "unknown")
        by_action[action] = by_action.get(action, 0) + 1
        by_protocol[protocol] = by_protocol.get(protocol, 0) + 1
    return {"total": len(rows), "by_action": by_action, "by_protocol": by_protocol}


def csv_export(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def alerts_csv_export(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=ALERT_FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def live_status() -> dict:
    services = {}
    for label, unit in (("suricata", "suricata"), ("nginx", "nginx"),
                        ("decision_engine", "adaptive-defender")):
        try:
            result = subprocess.run(["systemctl", "is-active", unit], capture_output=True,
                                    text=True, timeout=3, check=False)
            services[label] = result.stdout.strip() or "not-found"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            services[label] = "unavailable"
    return services


def _between(value: str, prefix: str, suffix: str) -> str | None:
    start = value.find(prefix)
    if start < 0:
        return None
    start += len(prefix)
    end = value.find(suffix, start)
    return None if end < 0 else value[start:end]


def read_rules(path: Path = RULES_PATH) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        sid = _between(stripped, "sid:", ";")
        severity = "unknown"
        if "metadata:severity " in stripped:
            severity = (_between(stripped, "metadata:severity ", ",") or
                        _between(stripped, "metadata:severity ", ";") or "unknown")
        rows.append({"line": line_number,
                     "sid": int(sid) if sid and sid.isdigit() else None,
                     "message": _between(stripped, 'msg:"', '";') or "unnamed rule",
                     "classtype": _between(stripped, "classtype:", ";") or "unknown",
                     "severity": severity, "enabled": True, "rule": stripped})
    return rows


def read_metrics(path: Path = BASELINE_PATH) -> dict:
    if not path.exists():
        return {"detection_accuracy": 0.0, "false_positive_rate": 0.0,
                "decision_latency_ms": 0.0, "redirect_latency_ms": 0.0}
    return calculate(json.loads(path.read_text(encoding="utf-8")))


def runtime_metrics(alerts: list[dict], decisions: list[dict]) -> dict:
    decision_latency = [float(row["decision_latency_ms"]) for row in decisions
                        if row.get("decision_latency_ms") is not None]
    redirect_latency = [float(row["redirect_latency_ms"]) for row in decisions
                        if row.get("redirect_latency_ms") is not None]
    redirects = sum(1 for row in decisions if "redirect" in str(row.get("action", "")))
    return {"source": "runtime", "detection_accuracy": None, "false_positive_rate": None,
            "decision_latency_ms": sum(decision_latency) / len(decision_latency) if decision_latency else None,
            "redirect_latency_ms": sum(redirect_latency) / len(redirect_latency) if redirect_latency else None,
            "total_alerts": len(alerts),
            "high_severity_alerts": sum(1 for row in alerts if int(row.get("severity") or 0) == 1),
            "total_decisions": len(decisions), "redirects": redirects,
            "temporary_blocks": sum(1 for row in decisions if row.get("action") == "temporary_block")}


def notifications(rows: list[dict], alerts: list[dict], status: dict) -> list[dict]:
    notes = []
    for name, state in status.items():
        if state not in {"active", "unknown"}:
            notes.append({"level": "warning", "title": f"{name} service is {state}",
                          "detail": "Run the production readiness check before deployment"})
    redirects = [row for row in rows if "redirect" in str(row.get("action", ""))]
    if redirects:
        latest = redirects[0]
        notes.append({"level": "high", "title": "Redirect decision recorded",
                      "detail": f"{latest.get('source_ip')} -> {latest.get('profile')}"})
    critical = [alert for alert in alerts if int(alert.get("severity") or 0) == 1]
    if critical:
        latest = critical[0]
        notes.append({"level": "critical", "title": "High severity Suricata alert",
                      "detail": f"SID {latest.get('signature_id')} from {latest.get('src_ip')}"})
    if not notes:
        notes.append({"level": "info", "title": "No actionable notifications",
                      "detail": "No event currently requires action"})
    return notes[:20]


@dataclass
class DashboardRuntime:
    settings: DashboardSettings

    def __post_init__(self) -> None:
        self.users = UserStore(self.settings.users_path)
        self.sessions = SessionStore(self.settings.session_ttl_seconds)
        self.limiter = LoginLimiter(self.settings.login_max_attempts,
                                    self.settings.login_window_seconds)
        self.alert_store = JsonlTail(self.settings.eve_paths, alert_transform,
                                     self.settings.maximum_rows)
        self.decision_store = JsonlTail((self.settings.decisions_path,), decision_transform,
                                        self.settings.maximum_rows)

    def status(self) -> dict:
        if self.settings.status_path.exists():
            try:
                return json.loads(self.settings.status_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
        return live_status()


def _default_settings(audit_path: Path, status_path: Path, eve_paths: tuple) -> DashboardSettings:
    return DashboardSettings(
        decisions_path=audit_path, status_path=status_path,
        eve_paths=tuple(Path(value) for value in eve_paths),
        users_path=PROJECT_ROOT / "config/users.json",
        security_audit_path=PROJECT_ROOT / "evidence/audit/dashboard-security.jsonl",
        active_rules_path=RULES_PATH, baseline_path=BASELINE_PATH,
        rule_registry_path=PROJECT_ROOT / "evidence/rules/registry.jsonl",
        rule_backup_dir=PROJECT_ROOT / "backups/rules",
        suricata_config_path=Path("/etc/suricata/suricata.yaml"))


def _query_rows(rows: list[dict], query: dict[str, list[str]], kind: str) -> tuple[list[dict], int, int, int]:
    search = (query.get("q") or [""])[0].lower().strip()
    if search:
        rows = [row for row in rows if search in json.dumps(row, sort_keys=True).lower()]
    severity = (query.get("severity") or [""])[0].lower().strip()
    if severity:
        rows = [row for row in rows if str(row.get("severity", "")).lower() == severity]
    protocol = (query.get("protocol") or [""])[0].lower().strip()
    if protocol:
        rows = [row for row in rows if protocol in {
            str(row.get("protocol", "")).lower(), str(row.get("proto", "")).lower(),
            str(row.get("app_proto", "")).lower()}]
    action = (query.get("action") or [""])[0].lower().strip()
    if action and kind == "decision":
        rows = [row for row in rows if str(row.get("action", "")).lower() == action]
    total = len(rows)
    try:
        limit = min(500, max(1, int((query.get("limit") or [100])[0])))
        offset = max(0, int((query.get("offset") or [0])[0]))
    except ValueError:
        limit, offset = 100, 0
    return rows[offset:offset + limit], total, limit, offset


def handler_factory(audit_path: Path | None = None, status_path: Path | None = None,
                    eve_paths: tuple = DEFAULT_EVE_PATHS,
                    settings: DashboardSettings | None = None):
    settings = settings or _default_settings(
        audit_path or PROJECT_ROOT / "evidence/test-results/decisions.jsonl",
        status_path or PROJECT_ROOT / "evidence/test-results/status.json", eve_paths)
    runtime = DashboardRuntime(settings)

    class Handler(BaseHTTPRequestHandler):
        server_version = "MIMICDashboard/1.0"

        def do_GET(self):
            parsed = urlparse(self.path)
            route, query = parsed.path, parse_qs(parsed.query)
            if route == "/":
                dashboard_file = Path(__file__).parent / "static/dashboard.html"
                self._send("text/html; charset=utf-8", dashboard_file.read_bytes())
                return
            if route == "/api/session.json":
                session = self._current_session()
                payload = None if session is None else {
                    "user": session.user, "csrf_token": session.csrf_token,
                    "expires_at": session.expires_at.isoformat()}
                self._send_json({"session": payload})
                return
            user = self._require_user()
            if user is None:
                return
            if route == "/api/alerts.json":
                items, total, limit, offset = _query_rows(runtime.alert_store.rows(), query, "alert")
                self._send_json({"items": items, "total": total, "limit": limit, "offset": offset})
            elif route == "/api/decisions.json":
                items, total, limit, offset = _query_rows(runtime.decision_store.rows(), query, "decision")
                self._send_json({"items": items, "total": total, "limit": limit, "offset": offset})
            elif route == "/api/alerts.csv":
                self._send_download("text/csv; charset=utf-8", alerts_csv_export(runtime.alert_store.rows()).encode(), "alerts.csv")
            elif route == "/api/decisions.csv":
                self._send_download("text/csv; charset=utf-8", csv_export(runtime.decision_store.rows()).encode(), "decisions.csv")
            elif route == "/api/summary.json":
                alerts, decisions = runtime.alert_store.rows(), runtime.decision_store.rows()
                payload = summary(decisions)
                payload["total_alerts"] = len(alerts)
                self._send_json(payload)
            elif route == "/api/status.json":
                self._send_json(runtime.status())
            elif route == "/api/metrics.json":
                self._send_json(runtime_metrics(runtime.alert_store.rows(), runtime.decision_store.rows()))
            elif route == "/api/notifications.json":
                self._send_json(notifications(runtime.decision_store.rows(), runtime.alert_store.rows(), runtime.status()))
            elif route in {"/api/rules.json", "/api/rule-registry.json"}:
                if not self._has_role(user, "master_admin"):
                    return
                self._send_json(read_rules(settings.active_rules_path) if route == "/api/rules.json"
                                else read_decisions(settings.rule_registry_path))
            else:
                self.send_error(404)

        def do_POST(self):
            route = urlparse(self.path).path
            if route == "/api/login":
                self._login()
                return
            user = self._require_user()
            if user is None or not self._require_csrf():
                return
            if route == "/api/logout":
                runtime.sessions.delete(self._session_token())
                append_security_audit(settings.security_audit_path, "logout", self.client_address[0], user["username"])
                self.send_response(204)
                self._security_headers()
                self.send_header("Set-Cookie", self._expired_cookie())
                self.end_headers()
            elif route in {"/api/rules/validate", "/api/rules/deploy"}:
                if self._has_role(user, "master_admin"):
                    self._rule_workflow(route, user)
            else:
                self.send_error(404)

        def _login(self) -> None:
            payload = self._read_json()
            username, password = str(payload.get("username", "")).strip(), str(payload.get("password", ""))
            key = f"{self.client_address[0]}:{username.lower()}"
            allowed, retry_after = runtime.limiter.check(key)
            if not allowed:
                append_security_audit(settings.security_audit_path, "login_rate_limited", self.client_address[0], username)
                self._send_json({"ok": False, "error": "rate_limited"}, 429,
                                {"Retry-After": str(retry_after)})
                return
            account = runtime.users.authenticate(username, password)
            if not account:
                runtime.limiter.failure(key)
                append_security_audit(settings.security_audit_path, "login_failed", self.client_address[0], username)
                self._send_json({"ok": False, "error": "invalid_login"}, 401)
                return
            runtime.limiter.success(key)
            token, session = runtime.sessions.create(account)
            append_security_audit(settings.security_audit_path, "login_succeeded", self.client_address[0], username)
            body = json.dumps({"ok": True, "user": account, "csrf_token": session.csrf_token}).encode()
            self.send_response(200)
            self._security_headers()
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", self._session_cookie(token))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _rule_workflow(self, route: str, user: dict) -> None:
            payload = self._read_json()
            payload.update({"reviewer": user["username"], "status": "candidate"})
            try:
                with tempfile.TemporaryDirectory() as directory:
                    candidate_path = Path(directory) / "candidate.json"
                    candidate_path.write_text(json.dumps(payload), encoding="utf-8")
                    report = validate(candidate_path, settings.active_rules_path, settings.baseline_path)
                if route == "/api/rules/validate":
                    append_security_audit(settings.security_audit_path, "rule_validated", self.client_address[0], user["username"], {"rule_id": payload.get("rule_id")})
                    self._send_json(report)
                    return
                if not settings.allow_rule_deploy:
                    self._send_json({"error": "rule_deploy_disabled", "validation": report}, 409)
                    return
                result = staged_deploy(payload, settings.active_rules_path,
                                       settings.rule_backup_dir, settings.rule_registry_path,
                                       self._suricata_syntax, self._reload_suricata,
                                       self._suricata_healthy, dry_run=False)
                append_security_audit(settings.security_audit_path, "rule_deploy", self.client_address[0], user["username"], result)
                self._send_json(result, 200 if result["status"] == "deployed" else 500)
            except (ValidationError, ValueError, KeyError, json.JSONDecodeError) as exc:
                append_security_audit(settings.security_audit_path, "rule_rejected", self.client_address[0], user["username"], {"reason": str(exc)})
                self._send_json({"error": "validation_failed", "detail": str(exc)}, 400)

        @staticmethod
        def _suricata_syntax(path: Path) -> bool:
            try:
                return subprocess.run(["suricata", "-T", "-c", str(settings.suricata_config_path),
                                       "-S", str(path)], capture_output=True, text=True,
                                      timeout=30, check=False).returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False

        @staticmethod
        def _reload_suricata() -> bool:
            try:
                return subprocess.run(["systemctl", "reload", "suricata"], timeout=15,
                                      check=False).returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False

        @staticmethod
        def _suricata_healthy() -> bool:
            try:
                return subprocess.run(["systemctl", "is-active", "--quiet", "suricata"],
                                      timeout=5, check=False).returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False

        def _read_json(self) -> dict:
            if self.headers.get_content_type() != "application/json":
                return {}
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 65536:
                return {}
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
                return value if isinstance(value, dict) else {}
            except (UnicodeDecodeError, json.JSONDecodeError):
                return {}

        def _session_token(self) -> str | None:
            raw = self.headers.get("Cookie")
            if not raw:
                return None
            try:
                jar = cookies.SimpleCookie(raw)
            except cookies.CookieError:
                return None
            morsel = jar.get("mimic_session")
            return morsel.value if morsel else None

        def _current_session(self) -> Session | None:
            return runtime.sessions.get(self._session_token())

        def _require_user(self) -> dict | None:
            session = self._current_session()
            if session is None:
                self._send_json({"error": "authentication_required"}, 401)
                return None
            return session.user

        def _require_csrf(self) -> bool:
            session = self._current_session()
            supplied = self.headers.get("X-CSRF-Token", "")
            if session is None or not supplied or supplied != session.csrf_token:
                self._send_json({"error": "csrf_failed"}, 403)
                return False
            return True

        def _has_role(self, user: dict, role: str) -> bool:
            if user.get("role") != role:
                self._send_json({"error": "forbidden"}, 403)
                return False
            return True

        def _session_cookie(self, token: str) -> str:
            secure = "; Secure" if settings.secure_cookie else ""
            return (f"mimic_session={token}; HttpOnly; SameSite=Strict; Path=/; "
                    f"Max-Age={settings.session_ttl_seconds}{secure}")

        def _expired_cookie(self) -> str:
            secure = "; Secure" if settings.secure_cookie else ""
            return f"mimic_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}"

        def _security_headers(self) -> None:
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")

        def _send_json(self, payload, status: int = 200, headers: dict | None = None):
            self._send("application/json", json.dumps(payload).encode(), status, headers)

        def _send(self, content_type: str, body: bytes, status: int = 200,
                  headers: dict | None = None):
            self.send_response(status)
            self._security_headers()
            self.send_header("Content-Type", content_type)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_download(self, content_type: str, body: bytes, filename: str):
            self._send(content_type, body, headers={"Content-Disposition": f'attachment; filename="{filename}"'})

        def log_message(self, format, *args):
            return

    return Handler


def create_server(settings: DashboardSettings) -> ThreadingHTTPServer:
    if settings.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("dashboard may bind only to loopback")
    return ThreadingHTTPServer((settings.host, settings.port), handler_factory(settings=settings))


def serve(audit_path: Path | None = None, status_path: Path | None = None,
          host: str = "127.0.0.1", port: int = 9090,
          eve_paths: tuple = DEFAULT_EVE_PATHS,
          settings: DashboardSettings | None = None):
    resolved = settings or _default_settings(
        audit_path or PROJECT_ROOT / "evidence/test-results/decisions.jsonl",
        status_path or PROJECT_ROOT / "evidence/test-results/status.json", eve_paths)
    if settings is None:
        resolved = DashboardSettings(**{**resolved.__dict__, "host": host, "port": port})
    create_server(resolved).serve_forever()
