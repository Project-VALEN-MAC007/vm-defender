from __future__ import annotations

import argparse
import json
import time

from .config import load_settings
from .engine import DecisionEngine


def main() -> int:
    parser = argparse.ArgumentParser(description="Adaptive Honeypot decision engine")
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true", help="process currently available complete events")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--dry-run", action="store_true", help="force adapters to validation-only mode")
    args = parser.parse_args()
    settings = load_settings(args.config)
    if args.dry_run and not settings.dry_run:
        settings = type(settings)(**{**settings.__dict__, "dry_run": True})
    engine = DecisionEngine(settings)
    if args.once:
        print(json.dumps(engine.run_once(), indent=2, sort_keys=True))
        return 0
    if not 0.1 <= args.poll_seconds <= 60:
        parser.error("--poll-seconds must be 0.1..60")
    while True:
        engine.run_once()
        time.sleep(args.poll_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
