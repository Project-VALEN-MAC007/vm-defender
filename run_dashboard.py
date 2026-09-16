#!/usr/bin/env python3
"""
VM-Defender Dashboard Runner
รัน dashboard บน http://127.0.0.1:9090
กด Ctrl+C เพื่อหยุด
"""

import argparse
from pathlib import Path
from defender.dashboard.app import serve
from defender.dashboard.config import load_dashboard_settings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the loopback-only MIMIC dashboard")
    parser.add_argument("--config", type=Path,
                        default=Path(__file__).parent / "config/mimic.json")
    args = parser.parse_args()
    if not args.config.is_file():
        parser.error(f"missing config: {args.config}; copy config/mimic.example.json and review it")
    settings = load_dashboard_settings(args.config)
    if not settings.users_path.is_file():
        parser.error("users file is missing; create an account with python -m defender.dashboard.manage_users")

    print("=" * 60)
    print("VM-Defender Dashboard")
    print("=" * 60)
    print(f"Config file: {args.config.resolve()}")
    print(f"Decisions file: {settings.decisions_path}")
    print(f"Security audit: {settings.security_audit_path}")
    print()
    print(f"Dashboard running at: http://{settings.host}:{settings.port}")
    print("Press Ctrl+C to stop")
    print("=" * 60)

    try:
        serve(settings=settings)
    except KeyboardInterrupt:
        print("\n\nDashboard stopped.")
