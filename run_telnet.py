#!/usr/bin/env python3
"""
Telnet Honeypot Runner
รัน telnet honeypot บน localhost:2323
กด Ctrl+C เพื่อหยุด
"""

from pathlib import Path
from defender.telnet.server import TelnetHoneypot

if __name__ == "__main__":
    project_root = Path(__file__).parent
    log_path = project_root / "evidence/telnet-logs/telnet.jsonl"

    print("=" * 60)
    print("🔌 Telnet Honeypot - VM-Defender")
    print("=" * 60)
    print(f"Log file: {log_path}")
    print()
    print("⚠️  WARNING: Binding to localhost only for safety")
    print("Telnet honeypot running at: telnet://127.0.0.1:2323")
    print("Press Ctrl+C to stop")
    print("=" * 60)

    try:
        honeypot = TelnetHoneypot(host="127.0.0.1", port=2323, log_path=log_path)
        honeypot.run()
    except KeyboardInterrupt:
        print("\n\nTelnet honeypot stopped.")
