from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class DashboardSettings:
    decisions_path: Path
    status_path: Path
    eve_paths: tuple[Path, ...]
    users_path: Path
    security_audit_path: Path
    active_rules_path: Path
    baseline_path: Path
    rule_registry_path: Path
    rule_backup_dir: Path
    suricata_config_path: Path
    host: str = "127.0.0.1"
    port: int = 9090
    session_ttl_seconds: int = 3600
    secure_cookie: bool = False
    login_max_attempts: int = 5
    login_window_seconds: int = 300
    maximum_rows: int = 5000
    allow_rule_deploy: bool = False


def _resolve(root: Path, value: str, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty path")
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def load_dashboard_settings(path: str | Path) -> DashboardSettings:
    config_path = Path(path).resolve()
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    root_value = raw.get("project_root", "..")
    root = _resolve(config_path.parent, root_value, "project_root")
    dashboard = raw.get("dashboard") or {}
    paths = raw.get("paths") or {}
    security = raw.get("security") or {}
    rules = raw.get("rules") or {}

    host = str(dashboard.get("host", "127.0.0.1"))
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("dashboard host must be loopback")
    port = int(dashboard.get("port", 9090))
    if not 1 <= port <= 65535:
        raise ValueError("dashboard port must be 1..65535")
    ttl = int(security.get("session_ttl_seconds", 3600))
    if not 300 <= ttl <= 86400:
        raise ValueError("session_ttl_seconds must be 300..86400")
    max_attempts = int(security.get("login_max_attempts", 5))
    if not 2 <= max_attempts <= 20:
        raise ValueError("login_max_attempts must be 2..20")

    eve_values = paths.get("eve_paths") or ["/var/log/suricata/eve.json"]
    if not isinstance(eve_values, list) or not eve_values:
        raise ValueError("paths.eve_paths must be a non-empty list")

    return DashboardSettings(
        decisions_path=_resolve(root, paths.get("decisions", "evidence/test-results/decisions.jsonl"), "paths.decisions"),
        status_path=_resolve(root, paths.get("status", "evidence/test-results/status.json"), "paths.status"),
        eve_paths=tuple(_resolve(root, value, "paths.eve_paths") for value in eve_values),
        users_path=_resolve(root, security.get("users_file", "config/users.json"), "security.users_file"),
        security_audit_path=_resolve(root, security.get("audit_log", "evidence/audit/dashboard-security.jsonl"), "security.audit_log"),
        active_rules_path=_resolve(root, rules.get("active_rules", "defender/suricata/rules/local.rules"), "rules.active_rules"),
        baseline_path=_resolve(root, rules.get("baseline", "tests/fixtures/baseline.json"), "rules.baseline"),
        rule_registry_path=_resolve(root, rules.get("registry", "evidence/rules/registry.jsonl"), "rules.registry"),
        rule_backup_dir=_resolve(root, rules.get("backup_dir", "backups/rules"), "rules.backup_dir"),
        suricata_config_path=_resolve(root, rules.get("suricata_config", "/etc/suricata/suricata.yaml"), "rules.suricata_config"),
        host=host,
        port=port,
        session_ttl_seconds=ttl,
        secure_cookie=bool(security.get("secure_cookie", False)),
        login_max_attempts=max_attempts,
        login_window_seconds=int(security.get("login_window_seconds", 300)),
        maximum_rows=int(dashboard.get("maximum_rows", 5000)),
        allow_rule_deploy=bool(rules.get("allow_deploy", False)),
    )
