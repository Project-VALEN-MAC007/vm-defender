from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import re
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import parse_qs, urlparse, quote, urlencode

from .config import DashboardSettings
from .data_store import JsonlTail, alert_transform, decision_transform
from .metrics import calculate
from .security import LoginLimiter, Session, SessionStore, UserStore, append_security_audit, verify_password
from .scope import (DashboardState, RuleStore, honeypot_transform, sessions_from_events,
                    extend_analytics, event_notifications, report_csv, threshold_config, stamp)
from .web_deploy import AgentError, DeployClient
from .rabbit import RabbitHoleService, log_rows as rabbit_log_rows, rabbit_transform
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
RULES_PATH = PROJECT_ROOT / "defender/suricata/rules/et-open-selected.rules"
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
        enabled = not stripped.startswith("# DISABLED ")
        if not enabled:
            stripped = stripped[11:]
        if not stripped or stripped.startswith("#"):
            continue
        sid = _between(stripped, "sid:", ";")
        severity = "unknown"
        if "metadata:severity " in stripped:
            severity = (_between(stripped, "metadata:severity ", ",") or
                        _between(stripped, "metadata:severity ", ";") or "unknown")
        else:
            match = re.search(r"\bsignature_severity\s+(\w+)", stripped)
            if match:
                severity = {"critical": "high", "major": "high", "minor": "medium",
                            "informational": "low"}.get(match.group(1).lower(), "unknown")
        rows.append({"line": line_number,
                     "sid": int(sid) if sid and sid.isdigit() else None,
                     "message": _between(stripped, 'msg:"', '";') or "unnamed rule",
                     "classtype": _between(stripped, "classtype:", ";") or "unknown",
                     "severity": severity, "enabled": enabled, "rule": stripped})
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
            "total_decisions": len(decisions), "redirects": redirects}


def _event_time(row: dict) -> datetime | None:
    value = row.get("timestamp") or row.get("start_time")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except ValueError:
        return None


def analytics(alerts: list[dict], decisions: list[dict], window: str = "24h",
              now: datetime | None = None, sessions: list[dict] | None = None) -> dict:
    """Aggregate the bounded runtime snapshot, never fixture or sample metrics."""
    if window not in {"24h", "7d", "30d", "all"}:
        raise ValueError("invalid window")
    now = now or datetime.now(timezone.utc)
    cutoff = None if window == "all" else now - {"24h": timedelta(hours=24),
                                                  "7d": timedelta(days=7),
                                                  "30d": timedelta(days=30)}[window]
    def in_window(row: dict) -> bool:
        stamp = _event_time(row)
        return stamp is not None and (cutoff is None or cutoff <= stamp <= now)
    alerts = [row for row in alerts if in_window(row)]
    decisions = [row for row in decisions if in_window(row)]
    trend = Counter()
    for row in alerts:
        stamp = _event_time(row).astimezone(timezone.utc)
        key = stamp.strftime("%Y-%m-%d %H:00") if window == "24h" else stamp.strftime("%Y-%m-%d")
        trend[key] += 1
    if window == "24h":
        keys = [(now - timedelta(hours=i)).astimezone(timezone.utc).strftime("%Y-%m-%d %H:00")
                for i in range(24, -1, -1)]
    elif window in {"7d", "30d"}:
        days = 7 if window == "7d" else 30
        keys = [(now - timedelta(days=i)).astimezone(timezone.utc).strftime("%Y-%m-%d")
                for i in range(days, -1, -1)]
    else:
        keys = sorted(trend)
    actions = Counter(str(row.get("action") or "unknown") for row in decisions)
    destinations = {"real": sum(count for action, count in actions.items()
                                 if action in {"allow", "monitor"}),
                    "honeypot": sum(count for action, count in actions.items()
                                    if action.startswith("redirect"))}
    result = {"window": window, "scope": "bounded_runtime_snapshot", "total_alerts": len(alerts),
            "unique_source_ips": len({row.get("src_ip") for row in alerts if row.get("src_ip")}),
            "high_severity_alerts": sum(str(row.get("severity")) == "1" for row in alerts),
            "total_decisions": len(decisions), "protocols": dict(Counter(
                str(row.get("app_proto") or row.get("proto") or "unknown").upper() for row in alerts)),
            "severities": dict(Counter(str(row.get("severity") or "unknown") for row in alerts)),
            "actions": dict(actions), "destinations": destinations,
            "trend": [{"time": key, "count": trend[key]} for key in keys],
            "honeypot_telemetry_available": False}
    sessions = [s for s in (sessions or []) if in_window({"timestamp": s.get("first_action")})]
    return extend_analytics(result, alerts, decisions, sessions)


def notifications(rows: list[dict], alerts: list[dict], status: dict) -> list[dict]:
    notes = []
    for name, state in status.items():
        if name == "demo":
            continue
        if state not in {"active", "unknown"}:
            notes.append({"level": "warning", "title": f"บริการ {name} มีสถานะ {state}",
                          "detail": "ตรวจสอบความพร้อมของระบบก่อนใช้งานจริง"})
    redirects = [row for row in rows if "redirect" in str(row.get("action", ""))]
    if redirects:
        latest = redirects[0]
        notes.append({"level": "high", "title": "มีการตัดสินใจเปลี่ยนเส้นทาง",
                      "detail": f"{latest.get('source_ip')} → {latest.get('profile')}"})
    critical = [alert for alert in alerts if int(alert.get("severity") or 0) == 1]
    if critical:
        latest = critical[0]
        notes.append({"level": "critical", "title": "Suricata พบเหตุการณ์ความรุนแรงสูง",
                      "detail": f"SID {latest.get('signature_id')} จาก {latest.get('src_ip')}"})
    if not notes:
        notes.append({"level": "info", "title": "ไม่มีการแจ้งเตือนที่ต้องดำเนินการ",
                      "detail": "ยังไม่พบเหตุการณ์ที่ต้องตรวจสอบเพิ่มเติม"})
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
        self.honeypot_store = JsonlTail(self.settings.honeypot_paths, honeypot_transform, self.settings.maximum_rows)
        self.state = DashboardState(self.settings.state_path or self.settings.users_path.with_name("dashboard-state.json"))
        self.rules = RuleStore(self.settings.active_rules_path, self.settings.rule_backup_dir,
                               self.settings.rule_apply_dir, direct_edit=self.settings.demo_mode)
        self.rabbit_store = JsonlTail(self.settings.rabbit_hole_log_paths, rabbit_transform,
                                      self.settings.maximum_rows)
        self.rabbit = RabbitHoleService(self.settings.rabbit_hole_config_path, PROJECT_ROOT)
        self.deploy = DeployClient(self.settings.deploy_agent_url, self.settings.deploy_agent_token_path)

    def alerts(self):
        return self.state.visible(self.alert_store.rows())

    def decisions(self):
        return self.state.visible(self.decision_store.rows())

    def sessions_data(self):
        # Rabbit Hole web sessions count as Web Honeypot sessions. They come from tracking
        # windows (split on idle timeout) so a returning scanner is not one multi-day session.
        return self.state.visible(sessions_from_events(self.honeypot_store.rows() + self.rabbit_sessions()))

    def rabbit_sessions(self):
        if not self.rabbit.available or not self.settings.rabbit_hole_log_paths:
            return []
        try:
            return self.rabbit.web_sessions(self.rabbit_store.rows())
        except (ValueError, OSError, KeyError):
            return []

    def rabbit_events(self):
        if not self.rabbit.available:
            return []
        return self.state.visible(self.rabbit.events(self.rabbit_store.rows(), self.honeypot_store.rows()))

    def rabbit_report(self, window):
        static = [s for s in self.state.visible(sessions_from_events(self.honeypot_store.rows()))
                  if s.get("profile") != "cowrie"]
        return self.rabbit.report(self.rabbit_events(), window, static)

    def report(self, window):
        result = analytics(self.alerts(), self.decisions(), window, sessions=self.sessions_data())
        if self.rabbit.available:
            try:
                result["rabbit_hole"] = self.rabbit_report(window)["summary"]
            except (ValueError, OSError, KeyError):
                result["rabbit_hole"] = None
        return result

    def event_notes(self):
        return event_notifications(self.decisions(), self.alerts(), self.sessions_data())

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


def search_logs(alerts: list[dict], decisions: list[dict], query: dict[str, list[str]], sessions: list[dict] | None = None,
                rabbit_events: list[dict] | None = None) -> dict:
    """Search all retained alert and decision rows before pagination."""
    rows = [{"type": "suricata", "time": a.get("timestamp"), "source": a.get("src_ip"),
             "protocol": a.get("app_proto") or a.get("proto"), "severity": a.get("severity"),
             "summary": a.get("signature") or a.get("category"), "result": "alert"}
            for a in alerts]
    rows += [{"type": "decision", "time": d.get("start_time"), "source": d.get("source_ip"),
              "protocol": d.get("protocol"), "severity": d.get("severity"),
              "summary": d.get("reason"), "result": d.get("action")}
             for d in decisions]
    rows += [{"type": "honeypot", "time": s["first_action"], "source": s["source_ip"],
              "protocol": s["profile"], "severity": None,
              "summary": f"Session {s['session_id']} · {s['actions']} actions · {s['dwell_seconds']:.1f}s",
              "result": s["profile"]} for s in (sessions or [])]
    rows += rabbit_log_rows(rabbit_events or [])
    def param(name: str) -> str:
        return str((query.get(name) or [""])[0]).strip()
    kind, source, protocol, severity = (param(name).lower() for name in
                                        ("type", "source", "protocol", "severity"))
    search = param("q").lower()
    if kind:
        rows = [r for r in rows if str(r["type"]).lower() == kind]
    if source:
        rows = [r for r in rows if source in str(r["source"] or "").lower()]
    if protocol:
        rows = [r for r in rows if str(r["protocol"] or "").lower() == protocol]
    if severity:
        rows = [r for r in rows if str(r["severity"] or "").lower() == severity]
    if search:
        rows = [r for r in rows if search in json.dumps(r, ensure_ascii=False).lower()]
    for field, lower_bound in (("from", True), ("to", False)):
        value = param(field)
        if value:
            try:
                bound = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if bound.tzinfo is None:
                    raise ValueError
            except ValueError as exc:
                raise ValueError("invalid time filter") from exc
            rows = [r for r in rows if (_event_time({"timestamp": r["time"]}) is not None and
                    (_event_time({"timestamp": r["time"]}) >= bound if lower_bound else
                     _event_time({"timestamp": r["time"]}) <= bound))]
    rows.sort(key=lambda r: _event_time({"timestamp": r["time"]}) or
              datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    total = len(rows)
    try:
        limit = min(500, max(1, int(param("limit") or 100)))
        offset = max(0, int(param("offset") or 0))
    except ValueError:
        limit, offset = 100, 0
    return {"items": rows[offset:offset + limit], "total": total, "limit": limit,
            "offset": offset, "scope": "bounded_runtime_snapshot"}


def handler_factory(audit_path: Path | None = None, status_path: Path | None = None,
                    eve_paths: tuple = DEFAULT_EVE_PATHS,
                    settings: DashboardSettings | None = None):
    settings = settings or _default_settings(
        audit_path or PROJECT_ROOT / "evidence/test-results/decisions.jsonl",
        status_path or PROJECT_ROOT / "evidence/test-results/status.json", eve_paths)
    runtime = DashboardRuntime(settings)

    class Handler(BaseHTTPRequestHandler):
        server_version = "TRAPDashboard/1.0"

        def do_GET(self):
            parsed = urlparse(self.path)
            route, query = parsed.path, parse_qs(parsed.query)
            if route == "/":
                dashboard_file = Path(__file__).parent / "static/dashboard.html"
                self._send("text/html; charset=utf-8", dashboard_file.read_bytes())
                return
            if route == "/static/dashboard.css":
                stylesheet = Path(__file__).parent / "static/dashboard.css"
                self._send("text/css; charset=utf-8", stylesheet.read_bytes())
                return
            if route == "/static/logo.svg":
                self._send("image/svg+xml", (Path(__file__).parent / "static/logo.svg").read_bytes())
                return
            if route == "/static/dashboard.js":
                script = Path(__file__).parent / "static/dashboard.js"
                self._send("application/javascript; charset=utf-8", script.read_bytes())
                return
            if route == "/static/guide.js":
                script = Path(__file__).parent / "static/guide.js"
                self._send("application/javascript; charset=utf-8", script.read_bytes())
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
                items, total, limit, offset = _query_rows(runtime.alerts(), query, "alert")
                self._send_json({"items": items, "total": total, "limit": limit, "offset": offset})
            elif route == "/api/decisions.json":
                items, total, limit, offset = _query_rows(runtime.decisions(), query, "decision")
                self._send_json({"items": items, "total": total, "limit": limit, "offset": offset})
            elif route == "/api/logs.json":
                try:
                    payload = search_logs(runtime.alerts(), runtime.decisions(), query, runtime.sessions_data(),
                                          runtime.rabbit_events())
                except ValueError:
                    self._send_json({"error": "invalid_time_filter"}, 400)
                else:
                    self._send_json(payload)
            elif route == "/api/alerts.csv":
                self._send_download("text/csv; charset=utf-8", alerts_csv_export(runtime.alerts()).encode(), "alerts.csv")
            elif route == "/api/decisions.csv":
                self._send_download("text/csv; charset=utf-8", csv_export(runtime.decisions()).encode(), "decisions.csv")
            elif route == "/api/summary.json":
                alerts, decisions = runtime.alerts(), runtime.decisions()
                payload = summary(decisions)
                payload["total_alerts"] = len(alerts)
                self._send_json(payload)
            elif route == "/api/status.json":
                self._send_json(runtime.status())
            elif route == "/api/metrics.json":
                self._send_json(runtime_metrics(runtime.alerts(), runtime.decisions()))
            elif route == "/api/analytics.json":
                window = (query.get("window") or ["24h"])[0]
                try:
                    payload = runtime.report(window)
                except ValueError:
                    self._send_json({"error": "invalid_window"}, 400)
                else:
                    self._send_json(payload)
            elif route == "/api/notifications.json":
                self._send_json(notifications(runtime.decisions(), runtime.alerts(), runtime.status()))
            elif route in {"/api/events.json", "/api/reports.csv", "/api/honeypot.json", "/api/capabilities.json", "/api/thresholds.json", "/api/rule-backups.json", "/api/candidates.json"}:
                self._scope_get(route, query, user)
            elif route.startswith("/api/rabbit-hole"):
                self._rabbit_get(route, query, user)
            elif route.startswith("/api/web-deploy/"):
                if self._has_role(user, "master_admin"):
                    self._deploy_get(route, query)
            elif route == "/api/users.json":
                if self._has_role(user, "master_admin"):
                    self._send_json({"items": runtime.users.list_public()})
            elif route in {"/api/rules.json", "/api/rule-registry.json"}:
                if not self._has_role(user, "master_admin"):
                    return
                self._send_json(read_rules(runtime.rules.source()) if route == "/api/rules.json"
                                else read_decisions(settings.rule_registry_path))
            else:
                self.send_error(404)

        def do_POST(self):
            route = urlparse(self.path).path
            if route in {"/api/login", "/api/login/totp"}:
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
            elif route == "/api/account/password":
                self._change_password(user)
            elif route in {"/api/account/totp/setup", "/api/account/totp/confirm"}:
                self._setup_totp(route, user)
            elif route == "/api/users":
                if self._has_role(user, "master_admin"):
                    self._create_user(user)
            elif route.startswith("/api/users/"):
                if self._has_role(user, "master_admin"):
                    self._manage_user(route, user)
            elif route == "/api/rabbit-hole/settings":
                if self._has_role(user, "master_admin"):
                    self._rabbit_save(user)
            elif route in {"/api/web-deploy/clone", "/api/web-deploy/activate"}:
                if self._has_role(user, "master_admin"):
                    self._deploy_post(route, user)
            elif route in {"/api/rabbit-hole/scenario/check", "/api/rabbit-hole/scenario/preview",
                           "/api/rabbit-hole/scenario/save", "/api/rabbit-hole/scenario/delete"}:
                if self._has_role(user, "master_admin"):
                    self._rabbit_scenario(route, user)
            elif route in {"/api/events/update", "/api/logs/flush", "/api/thresholds", "/api/rules/change", "/api/candidates/save", "/api/candidates/approve"}:
                self._scope_post(route, user)
            else:
                self.send_error(404)

        def _scope_get(self, route, query, user):
            if route in {"/api/thresholds.json", "/api/rule-backups.json", "/api/candidates.json"} and not self._has_role(user, "master_admin"):
                return
            try:
                if route == "/api/events.json":
                    self._send_json(runtime.state.notifications(user["username"], runtime.event_notes(), query))
                elif route == "/api/reports.csv":
                    report = runtime.report((query.get("window") or ["24h"])[0])
                    self._send_download("text/csv; charset=utf-8", report_csv(report).encode("utf-8"), "trap-report.csv")
                elif route == "/api/honeypot.json":
                    self._send_json({"items": runtime.sessions_data()[:100]})
                elif route == "/api/capabilities.json":
                    self._send_json({"rule_edit_available": runtime.rules.editable,
                                     "rule_apply": runtime.rules.apply_status(),
                                     "default_password_change": settings.force_default_password_change,
                                     "flush_requires_totp": True})
                elif route == "/api/thresholds.json":
                    self._send_json(threshold_config(settings.engine_config_path))
                elif route == "/api/rule-backups.json":
                    self._send_json({"items": runtime.rules.backups()})
                elif route == "/api/candidates.json":
                    self._send_json({"items": list(runtime.state.load().get("candidates", {}).values())})
            except (ValueError, OSError) as exc:
                self._send_json({"error": str(exc)}, 400)

        def _rabbit_get(self, route, query, user):
            if not runtime.rabbit.available:
                self._send_json({"error": "rabbit_hole_not_configured"}, 404)
                return
            admin_only = {"/api/rabbit-hole/preview.json", "/api/rabbit-hole/cowrie-bundle.zip",
                          "/api/rabbit-hole/scenario.json"}
            if route in admin_only and not self._has_role(user, "master_admin"):
                return
            try:
                if route == "/api/rabbit-hole.json":
                    self._send_json(runtime.rabbit_report((query.get("window") or ["24h"])[0]))
                elif route == "/api/rabbit-hole/window.json":
                    self._send_json(runtime.rabbit.window_detail(runtime.rabbit_events(),
                                                                 (query.get("id") or [""])[0]))
                elif route == "/api/rabbit-hole/preview.json":
                    self._send_json(runtime.rabbit.preview((query.get("scenario") or [""])[0]))
                elif route == "/api/rabbit-hole/scenario.json":
                    self._send_json(runtime.rabbit.definition((query.get("id") or [""])[0]))
                elif route == "/api/rabbit-hole/cowrie-bundle.zip":
                    self._send_download("application/zip", runtime.rabbit.bundle(), "rabbit-hole-cowrie.zip")
                else:
                    self.send_error(404)
            except (ValueError, OSError, KeyError) as exc:
                self._send_json({"error": str(exc)}, 400)

        def _deploy_get(self, route, query):
            value = lambda name: (query.get(name) or [""])[0]
            try:
                if route == "/api/web-deploy/status.json":
                    result = runtime.deploy.status()
                elif route == "/api/web-deploy/job.json":
                    result = runtime.deploy.job(value("id"))
                elif route == "/api/web-deploy/pages.json":
                    result = runtime.deploy.pages(value("version"))
                elif route == "/api/web-deploy/page.json":
                    result = runtime.deploy.page(value("version"), value("url") or "/index.html")
                else:
                    self.send_error(404)
                    return
            except AgentError as exc:
                self._send_json({"error": str(exc)}, exc.status)
                return
            self._send_json(result)

        def _deploy_post(self, route, user):
            payload = self._read_json()
            try:
                if route == "/api/web-deploy/clone":
                    depth = payload.get("depth")
                    result = runtime.deploy.clone(str(payload.get("url", "")), depth if isinstance(depth, int) else 0)
                    audit = {"url": payload.get("url"), "depth": depth}
                else:
                    # Switching what attackers see is a production change: re-check the
                    # password, and the TOTP code when the account has one.
                    key = "deploy:" + user["username"]
                    allowed, retry = runtime.limiter.check(key)
                    if not allowed:
                        self._send_json({"error": "rate_limited"}, 429, {"Retry-After": str(retry)})
                        return
                    account = runtime.users.begin_login(user["username"], str(payload.get("password", "")),
                                                        require_totp=False)
                    if (payload.get("confirmation") != "DEPLOY" or not account or
                            (account.get("totp_enabled") and
                             not runtime.users.verify_totp_action(user["username"], str(payload.get("totp", ""))))):
                        runtime.limiter.failure(key)
                        self._send_json({"error": "deploy_confirmation_failed"}, 403)
                        return
                    runtime.limiter.success(key)
                    result = runtime.deploy.activate(str(payload.get("version", "")))
                    audit = {"version": payload.get("version")}
            except AgentError as exc:
                self._send_json({"error": str(exc)}, exc.status)
                return
            append_security_audit(settings.security_audit_path, "web_deploy_" + route.rsplit("/", 1)[1],
                                  self.client_address[0], user["username"], audit)
            self._send_json(result, 202)

        def _rabbit_scenario(self, route, user):
            if not runtime.rabbit.available:
                self._send_json({"error": "rabbit_hole_not_configured"}, 404)
                return
            payload = self._read_json()
            action = route.rsplit("/", 1)[1]
            try:
                if action == "check":
                    result = runtime.rabbit.check_draft(payload.get("definition") or {})
                elif action == "preview":
                    result = runtime.rabbit.preview_draft(payload.get("definition") or {})
                elif action == "save":
                    result = runtime.rabbit.save_scenario(payload.get("definition") or {})
                else:
                    result = runtime.rabbit.delete_scenario(payload.get("id"))
            except (ValueError, OSError, KeyError, TypeError) as exc:
                self._send_json({"error": str(exc)}, 400)
                return
            if action in {"save", "delete"}:
                append_security_audit(settings.security_audit_path, "rabbit_hole_scenario_" + action,
                                      self.client_address[0], user["username"],
                                      {"scenario": result.get("id") or payload.get("id")})
            self._send_json(result)

        def _rabbit_save(self, user):
            payload = self._read_json()
            try:
                result = runtime.rabbit.save(payload)
            except (ValueError, OSError, KeyError, TypeError) as exc:
                self._send_json({"error": str(exc)}, 400)
                return
            append_security_audit(settings.security_audit_path, "rabbit_hole_settings", self.client_address[0],
                                  user["username"], {"enabled": result["settings"]["enabled"],
                                                     "scenarios": result["settings"]["scenarios"]})
            self._send_json(result)

        def _scope_post(self, route, user):
            if route not in {"/api/events/update", "/api/logs/flush"} and not self._has_role(user, "master_admin"):
                return
            payload = self._read_json()
            try:
                if route == "/api/events/update":
                    runtime.state.mark(user["username"], payload.get("id"), payload.get("action"),
                                       {r["id"] for r in runtime.event_notes()})
                    result = {"ok": True}
                elif route == "/api/logs/flush":
                    key = "flush:" + user["username"]
                    allowed, retry = runtime.limiter.check(key)
                    if not allowed:
                        self._send_json({"error": "rate_limited"}, 429, {"Retry-After": str(retry)})
                        return
                    if payload.get("confirmation") != "FLUSH" or not runtime.users.verify_totp_action(user["username"], payload.get("totp", "")):
                        runtime.limiter.failure(key)
                        self._send_json({"error": "flush_totp_required"}, 403)
                        return
                    runtime.state.flush()
                    result = {"ok": True}
                elif route == "/api/thresholds":
                    result = threshold_config(settings.engine_config_path, payload)
                elif route == "/api/rules/change":
                    if not runtime.rules.editable:
                        self._send_json({"error": "live_rule_edit_requires_deployment_helper"}, 409)
                        return
                    result = runtime.rules.change(payload)
                elif route == "/api/candidates/save":
                    payload.update(reviewer=user["username"], status="candidate")
                    with tempfile.TemporaryDirectory() as directory:
                        path = Path(directory) / "candidate.json"
                        path.write_text(json.dumps(payload), encoding="utf-8")
                        report = validate(path, runtime.rules.source(), settings.baseline_path)
                    with runtime.state.lock:
                        data = runtime.state.load()
                        data.setdefault("candidates", {})[payload["rule_id"]] = {**payload, "test_results": report, "status": "pending"}
                        runtime.state.save(data)
                    result = {"ok": True, "test_results": report}
                elif route == "/api/candidates/approve":
                    if not runtime.rules.editable:
                        self._send_json({"error": "live_rule_edit_requires_deployment_helper"}, 409)
                        return
                    with runtime.state.lock:
                        data = runtime.state.load()
                        candidate = data.get("candidates", {}).get(payload.get("rule_id"))
                        if not candidate or candidate["status"] != "pending":
                            raise ValueError("candidate_not_pending")
                        # Revalidate immediately before approval, including duplicate SID.
                        with tempfile.TemporaryDirectory() as directory:
                            path = Path(directory) / "candidate.json"
                            path.write_text(json.dumps({**candidate, "status": "candidate"}), encoding="utf-8")
                            validate(path, runtime.rules.source(), settings.baseline_path)
                        result = runtime.rules.change({"action": "add", "rule": candidate["rule"]})
                        candidate["status"] = "approved"
                        runtime.state.save(data)
                else:
                    raise ValueError("unknown_operation")
            except (ValueError, OSError, KeyError, TypeError) as exc:
                self._send_json({"error": str(exc)}, 400)
                return
            append_security_audit(settings.security_audit_path, route[5:],
                                  self.client_address[0], user["username"],
                                  {"action": payload.get("action"), "target": payload.get("id") or payload.get("sid")})
            self._send_json(result)

        def _create_user(self, actor: dict) -> None:
            payload = self._read_json()
            try:
                password = payload.get("password")
                if not password:
                    # The admin always sets the first password; it is never generated.
                    raise ValueError("invalid_password")
                account, password = runtime.users.create_user(
                    str(payload.get("username", "")), str(payload.get("name", "")), password)
            except ValueError as exc:
                self._send_json({"error": str(exc)}, 409 if str(exc) == "username_exists" else 400)
                return
            except OSError:
                self._send_json({"error": "user_store_unavailable"}, 503)
                return
            append_security_audit(settings.security_audit_path, "user_created", self.client_address[0],
                                  actor["username"], {"target": account["username"]})
            result = {"user": account}
            if password is not None:
                result["temporary_password"] = password
            self._send_json(result, 201)

        def _manage_user(self, route: str, actor: dict) -> None:
            parts = route.split("/")
            if len(parts) != 5 or parts[4] not in {"status", "reset-password", "edit", "delete"}:
                self.send_error(404)
                return
            username, action = parts[3], parts[4]
            try:
                if action == "status":
                    payload = self._read_json()
                    if type(payload.get("disabled")) is not bool:
                        self._send_json({"error": "invalid_status"}, 400)
                        return
                    account = runtime.users.set_disabled(username, payload["disabled"])
                    result = {"user": account}
                elif action == "reset-password":
                    result = {"temporary_password": runtime.users.reset_password(username)}
                else:
                    payload = self._read_json()
                    account = runtime.users.load().get(username)
                    if not account:
                        raise ValueError("user_not_found")
                    result = {"user": runtime.users.edit_user(username, payload.get("name", account["name"]),
                              payload.get("role", account["role"]), delete=action == "delete")}
            except ValueError as exc:
                self._send_json({"error": str(exc)}, 404)
                return
            except OSError:
                self._send_json({"error": "user_store_unavailable"}, 503)
                return
            runtime.sessions.delete_user(username)
            append_security_audit(settings.security_audit_path, "user_" + action.replace("-", "_"),
                                  self.client_address[0], actor["username"], {"target": username})
            self._send_json(result)

        def _change_password(self, user: dict) -> None:
            payload = self._read_json()
            current, new = payload.get("current_password"), payload.get("new_password")
            if not isinstance(current, str) or not isinstance(new, str):
                self._send_json({"error": "invalid_password"}, 400)
                return
            try:
                runtime.users.change_password(user["username"], current, new)
            except ValueError as exc:
                self._send_json({"error": str(exc)}, 400)
                return
            except OSError:
                self._send_json({"error": "user_store_unavailable"}, 503)
                return
            runtime.sessions.delete_user(user["username"])
            append_security_audit(settings.security_audit_path, "password_changed", self.client_address[0],
                                  user["username"])
            self._send_json({"ok": True}, headers={"Set-Cookie": self._expired_cookie()})

        def _setup_totp(self, route: str, user: dict) -> None:
            payload = self._read_json()
            password = payload.get("current_password")
            code = payload.get("totp") if route.endswith("/confirm") else None
            if not isinstance(password, str) or (route.endswith("/confirm") and not isinstance(code, str)):
                self._send_json({"error": "invalid_input"}, 400)
                return
            key = f"totp:{self.client_address[0]}:{user['username']}"
            allowed, retry = runtime.limiter.check(key)
            if not allowed:
                self._send_json({"error": "rate_limited"}, 429, {"Retry-After": str(retry)})
                return
            try:
                secret = runtime.users.setup_totp(user["username"], password, code)
            except ValueError as error:
                runtime.limiter.failure(key)
                self._send_json({"error": str(error)}, 400)
                return
            if secret:
                uri = "otpauth://totp/" + quote("TRAP:" + user["username"], safe="") + "?" + urlencode({
                    "secret": secret, "issuer": "TRAP", "algorithm": "SHA1", "digits": 6, "period": 30})
                self._send_json({"secret": secret, "otpauth_uri": uri})
            else:
                runtime.sessions.delete_user(user["username"])
                append_security_audit(settings.security_audit_path, "totp_enabled", self.client_address[0], user["username"])
                self._send_json({"ok": True})

        def _login(self) -> None:
            payload = self._read_json()
            username, password = str(payload.get("username", "")).strip(), str(payload.get("password", ""))
            if urlparse(self.path).path == "/api/login/totp":
                username = ""
            key = f"{self.client_address[0]}:{username.lower()}"
            allowed, retry_after = runtime.limiter.check(key)
            if not allowed:
                append_security_audit(settings.security_audit_path, "login_rate_limited", self.client_address[0], username)
                self._send_json({"ok": False, "error": "rate_limited"}, 429,
                                {"Retry-After": str(retry_after)})
                return
            if urlparse(self.path).path == "/api/login/totp":
                account = runtime.users.complete_login(payload.get("challenge"), payload.get("totp", ""))
            else:
                account = runtime.users.begin_login(username, password, require_totp=settings.require_totp)
            if not account:
                runtime.limiter.failure(key)
                append_security_audit(settings.security_audit_path, "login_failed", self.client_address[0], username)
                self._send_json({"ok": False, "error": "invalid_login"}, 401)
                return
            if account.get("totp_required"):
                self._send_json({"ok": True, **account})
                return
            username = account["username"]
            runtime.limiter.success(key)
            runtime.limiter.success(f"{self.client_address[0]}:{username.lower()}")
            stored = runtime.users.load()[username]
            account["must_change_password"] = bool(settings.force_default_password_change and
                account["role"] == "master_admin" and (stored["must_change_password"] or verify_password("admin", stored["password_hash"])))
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
            limit = 1048576 if urlparse(self.path).path.startswith("/api/rabbit-hole/scenario/") else 65536
            if length <= 0 or length > limit:
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
            morsel = jar.get("trap_session")
            return morsel.value if morsel else None

        def _current_session(self) -> Session | None:
            token = self._session_token()
            session = runtime.sessions.get(token)
            if session:
                account = runtime.users.load().get(session.user["username"])
                if not account or account["disabled"] or account["role"] != session.user["role"]:
                    runtime.sessions.delete(token)
                    return None
            return session

        def _require_user(self) -> dict | None:
            session = self._current_session()
            if session is None:
                self._send_json({"error": "authentication_required"}, 401)
                return None
            if session.user.get("must_change_password") and urlparse(self.path).path not in {
                    "/api/account/password", "/api/logout", "/api/account/totp/setup", "/api/account/totp/confirm"}:
                self._send_json({"error": "password_change_required"}, 403)
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
            return (f"trap_session={token}; HttpOnly; SameSite=Strict; Path=/; "
                    f"Max-Age={settings.session_ttl_seconds}{secure}")

        def _expired_cookie(self) -> str:
            secure = "; Secure" if settings.secure_cookie else ""
            return f"trap_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}"

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
