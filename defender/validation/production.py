from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path

from defender.dashboard.config import load_dashboard_settings

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def assess_config(path: Path) -> dict:
    checks = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "status": "passed" if passed else "blocked",
                       "detail": detail})

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        settings = load_dashboard_settings(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"ready": False, "checks": [{"name": "config", "status": "blocked",
                                               "detail": str(exc)}]}

    network = raw.get("network") or {}
    interfaces = [str(network.get(name, "")) for name in
                  ("management_interface", "outer_interface", "inner_interface")]
    configured = all(value and value != "CHANGE_ME" for value in interfaces)
    add("network_interfaces_configured", configured,
        "all Defender interfaces are named" if configured else "replace every CHANGE_ME interface")
    add("network_interfaces_distinct", len(set(interfaces)) == 3 and configured,
        "management, outer and inner interfaces are distinct")
    try:
        outer = ipaddress.ip_address(str(network.get("outer_ip", "")))
        inner = ipaddress.ip_address(str(network.get("inner_ip", "")))
        valid_ips = outer.version == inner.version == 4 and outer != inner and not outer.is_loopback and not inner.is_loopback
    except ValueError:
        valid_ips = False
    add("network_addresses_valid", valid_ips, "outer and inner IPv4 addresses are distinct and non-loopback")
    add("dashboard_loopback_only", settings.host in {"127.0.0.1", "::1", "localhost"},
        f"dashboard bind is {settings.host}")
    add("dashboard_users_present", settings.users_path.is_file(),
        f"user store: {settings.users_path}")
    add("rule_live_deploy_guard", not settings.allow_rule_deploy,
        "dashboard rule deployment remains disabled until privileged helper review")
    lab_path = PROJECT_ROOT / "defender/decision_engine/config/lab.json"
    try:
        lab_dry_run = bool(json.loads(lab_path.read_text(encoding="utf-8")).get("dry_run"))
    except (OSError, ValueError, json.JSONDecodeError):
        lab_dry_run = False
    add("lab_config_dry_run", lab_dry_run, "lab decision engine defaults to validation-only mode")
    return {"ready": all(item["status"] == "passed" for item in checks), "checks": checks}


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only MIMIC production configuration gate")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = assess_config(args.config)
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if report["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
