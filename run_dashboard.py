#!/usr/bin/env python3
"""
VM-Defender Dashboard Runner
รัน dashboard บน http://127.0.0.1:9090
กด Ctrl+C เพื่อหยุด
"""

from pathlib import Path
from defender.dashboard.app import serve

if __name__ == "__main__":
    project_root = Path(__file__).parent
    decisions_path = project_root / "evidence/test-results/decisions.jsonl"
    status_path = project_root / "evidence/test-results/status.json"

    print("=" * 60)
    print("🛡️  VM-Defender Dashboard")
    print("=" * 60)
    print(f"Decisions file: {decisions_path}")
    print(f"Status file: {status_path}")
    print()
    print("Dashboard running at: http://127.0.0.1:9090")
    print("Press Ctrl+C to stop")
    print("=" * 60)

    try:
        serve(decisions_path, status_path)
    except KeyboardInterrupt:
        print("\n\nDashboard stopped.")
