"""Rabbit Hole configuration: organisation profile, chosen scenarios and limits."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import date, datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets

from . import scenario as scenario_mod
from .render import Faker

DEFAULTS = {
    "enabled": True,
    "organization": {
        "name": "Example Co., Ltd.",
        "short_name": "example",
        "domain": "example.local",
        "hostname": "web-prod-01",
        "admin_user": "sysadmin",
        "db_name": "example_erp",
        "internal_subnet": "10.20.0",
    },
    "scenarios": {"web": ["web-backup-api", "web-env-admin"], "shell": "linux-server"},
    "limits": {
        "max_depth": 5,
        "max_branches": 2,
        "max_resources_per_session": 40,
        "idle_timeout_seconds": 300,
        "session_ttl_seconds": 3600,
        "max_sessions": 5000,
    },
    "web": {
        "host": "127.0.0.1",
        "port": 8084,
        "log_path": "evidence/rabbit-hole/web.jsonl",
        "trusted_proxies": ["127.0.0.1/32"],
        "server_header": "nginx/1.24.0",
    },
    "secret_path": "config/rabbit-hole.secret",
    "custom_scenario_dir": "config/rabbit-hole-scenarios",
    "extra_scenario_dirs": [],
}
ORG_FIELD = re.compile(r"^[A-Za-z0-9 .,&()'_-]{1,80}$")
HOST_FIELD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
USER_FIELD = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SUBNET_FIELD = re.compile(r"^(10|172|192)\.\d{1,3}\.\d{1,3}$")
LIMIT_RANGES = {
    "max_depth": (1, 10),
    "max_branches": (1, 5),
    "max_resources_per_session": (1, 500),
    "idle_timeout_seconds": (30, 3600),
    "session_ttl_seconds": (300, 86400),
    "max_sessions": (10, 100000),
}


def _merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def validate_raw(raw: dict) -> dict:
    """Validate and normalise a raw config dict. Raises ValueError with a short code."""
    data = _merge(DEFAULTS, raw)
    if not isinstance(data["enabled"], bool):
        raise ValueError("enabled_must_be_boolean")
    org = data["organization"]
    for key in ("name", "short_name"):
        if not isinstance(org.get(key), str) or not ORG_FIELD.match(org[key]):
            raise ValueError(f"invalid_organization_{key}")
    for key in ("domain", "hostname"):
        if not isinstance(org.get(key), str) or not HOST_FIELD.match(org[key]):
            raise ValueError(f"invalid_organization_{key}")
    for key in ("admin_user", "db_name"):
        if not isinstance(org.get(key), str) or not USER_FIELD.match(org[key]):
            raise ValueError(f"invalid_organization_{key}")
    if not isinstance(org.get("internal_subnet"), str) or not SUBNET_FIELD.match(org["internal_subnet"]):
        raise ValueError("invalid_organization_internal_subnet")
    if any(int(p) > 255 for p in org["internal_subnet"].split(".")):
        raise ValueError("invalid_organization_internal_subnet")
    limits = data["limits"]
    for key, (low, high) in LIMIT_RANGES.items():
        value = limits.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"invalid_limit_{key}")
    scenarios = data["scenarios"]
    web = scenarios.get("web")
    if not isinstance(web, list) or not all(isinstance(x, str) for x in web):
        raise ValueError("invalid_web_scenarios")
    shell = scenarios.get("shell")
    if shell is not None and not isinstance(shell, str):
        raise ValueError("invalid_shell_scenario")
    web_cfg = data["web"]
    if web_cfg.get("host") not in {"127.0.0.1", "::1", "localhost", "0.0.0.0"} and not _is_ip(web_cfg.get("host")):
        raise ValueError("invalid_web_host")
    port = web_cfg.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("invalid_web_port")
    for cidr in web_cfg.get("trusted_proxies") or []:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError("invalid_trusted_proxy") from exc
    return data


def _is_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


@dataclass
class RabbitConfig:
    path: Path | None
    root: Path
    data: dict

    @property
    def enabled(self) -> bool:
        return bool(self.data["enabled"])

    @property
    def organization(self) -> dict:
        return self.data["organization"]

    @property
    def limits(self) -> dict:
        return self.data["limits"]

    @property
    def web(self) -> dict:
        return self.data["web"]

    def resolve(self, value: str) -> Path:
        path = Path(value)
        return path if path.is_absolute() else (self.root / path)

    @property
    def log_path(self) -> Path:
        return self.resolve(self.web["log_path"])

    def secret(self) -> bytes:
        """Per-deployment secret; created on first use and never shown on the dashboard."""
        path = self.resolve(self.data["secret_path"])
        if path.is_file():
            value = path.read_text(encoding="utf-8").strip()
            if len(value) >= 32:
                return value.encode("utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        value = secrets.token_hex(32)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(value + "\n", encoding="utf-8")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
        return value.encode("utf-8")

    def anchor_date(self) -> date:
        """Fixed date of this deployment (secret creation), so dated decoy paths
        such as ``users_export_<date>.csv`` stay the same from day to day."""
        self.secret()
        path = self.resolve(self.data["secret_path"])
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).date()

    def deployment_faker(self, today: date | None = None) -> Faker:
        return Faker(self.secret(), "deployment", self.organization, today or self.anchor_date())

    @property
    def custom_dir(self) -> Path:
        return self.resolve(self.data.get("custom_scenario_dir") or "config/rabbit-hole-scenarios")

    def scenario_dirs(self) -> list:
        return [self.custom_dir] + [self.resolve(d) for d in self.data.get("extra_scenario_dirs") or []]

    def all_scenarios(self, errors: list | None = None) -> dict:
        return scenario_mod.available(self.scenario_dirs(), errors)

    def scenario_signature(self) -> tuple:
        """Changes whenever a scenario file is added, edited or removed."""
        items = []
        for directory in self.scenario_dirs():
            if directory.is_dir():
                items += [(str(p), p.stat().st_mtime) for p in sorted(directory.glob("*.json"))]
        return tuple(items)

    def selected(self, protocol: str) -> list:
        """Selected scenarios with paths resolved for this deployment."""
        catalog = self.all_scenarios()
        names = self.data["scenarios"]["web"] if protocol == "web" else (
            [self.data["scenarios"]["shell"]] if self.data["scenarios"].get("shell") else [])
        faker = self.deployment_faker()
        chosen = []
        for name in names:
            if name not in catalog:
                raise ValueError(f"unknown_scenario:{name}")
            item = catalog[name]
            if item.protocol != protocol:
                raise ValueError(f"scenario_protocol_mismatch:{name}")
            chosen.append(scenario_mod.resolve_paths(item, faker))
        return chosen

    def problems(self) -> list:
        """Validation report used by the CLI and dashboard before enabling a config."""
        issues = []
        try:
            catalog = self.all_scenarios()
        except scenario_mod.ScenarioError as exc:
            return [str(exc)]
        names = list(self.data["scenarios"]["web"])
        if self.data["scenarios"].get("shell"):
            names.append(self.data["scenarios"]["shell"])
        for name in names:
            if name not in catalog:
                issues.append(f"unknown scenario {name}")
                continue
            issues += scenario_mod.check_limits(catalog[name], self.limits)
            issues += scenario_mod.check_templates(catalog[name], self.organization)
        try:
            seen = {}
            for item in self.selected("web"):
                for node in item.nodes.values():
                    if node.path in seen:
                        issues.append(f"path {node.path} used by {seen[node.path]} and {item.id}")
                    seen[node.path] = item.id
        except (ValueError, KeyError) as exc:
            issues.append(str(exc))
        return issues

    def public(self) -> dict:
        """Config without secrets for the dashboard."""
        data = copy.deepcopy(self.data)
        data.pop("secret_path", None)
        data.pop("custom_scenario_dir", None)
        data.pop("extra_scenario_dirs", None)
        return data

    def save(self, data: dict) -> "RabbitConfig":
        if self.path is None:
            raise ValueError("rabbit_hole_config_path_missing")
        current = self.data
        merged = _merge(current, data)
        merged["secret_path"] = current["secret_path"]
        merged["web"] = current["web"]
        merged["extra_scenario_dirs"] = current.get("extra_scenario_dirs", [])
        merged["custom_scenario_dir"] = current.get("custom_scenario_dir")
        validated = validate_raw(merged)
        candidate = RabbitConfig(self.path, self.root, validated)
        issues = candidate.problems()
        if issues:
            raise ValueError("scenario_check_failed: " + "; ".join(issues[:5]))
        raw = json.loads(self.path.read_text(encoding="utf-8")) if self.path.is_file() else {}
        raw.update({k: validated[k] for k in ("enabled", "organization", "scenarios", "limits")})
        temporary = self.path.with_name(self.path.name + "." + secrets.token_hex(4) + ".tmp")
        temporary.write_text(json.dumps(raw, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(temporary, self.path)
        return candidate


def load(path: str | Path | None, root: Path | None = None) -> RabbitConfig:
    if path is None:
        return RabbitConfig(None, root or Path.cwd(), validate_raw({}))
    path = Path(path).resolve()
    raw = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    project_root = raw.get("project_root")
    if root is None:
        root = (path.parent / project_root).resolve() if project_root else path.parent.parent
    return RabbitConfig(path, root, validate_raw({k: v for k, v in raw.items() if k != "project_root"}))
