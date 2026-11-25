"""Command line for Rabbit Hole.

  python -m defender.rabbit_hole check  --config config/rabbit-hole.json
  python -m defender.rabbit_hole serve  --config config/rabbit-hole.json
  python -m defender.rabbit_hole preview --config config/rabbit-hole.json [--session demo]
  python -m defender.rabbit_hole cowrie-bundle --config config/rabbit-hole.json --out bundle.zip
  python -m defender.rabbit_hole plan --config /var/lib/trap/rabbit-hole.json \
      --decisions /var/log/adaptive-defender/decisions.jsonl --eve /var/log/suricata/eve.json \
      --web-log /var/log/trap/honeypot/rabbit-hole-web.jsonl --out /var/lib/trap/rabbit-hole-plan.json \
      --push-command "/opt/trap/deploy/trap-sync.sh plan"      (Defender only; Jev picks the clues)
  python -m defender.rabbit_hole cowrie-install --config /var/lib/trap/rabbit-hole.json \
      --fs-pickle /home/cowrie/cowrie/src/cowrie/data/fs.pickle --honeyfs /home/cowrie/cowrie/honeyfs \
      --restart-cmd "systemctl restart cowrie"
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import shell
from .config import load
from .render import Faker, render


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m defender.rabbit_hole")
    parser.add_argument("command", choices=["check", "serve", "preview", "cowrie-bundle", "cowrie-install", "plan"])
    parser.add_argument("--config", default="config/rabbit-hole.json")
    parser.add_argument("--session", default="preview")
    parser.add_argument("--out", default="rabbit-hole-cowrie.zip")
    parser.add_argument("--fs-pickle", help="Cowrie fs.pickle (cowrie-install)")
    parser.add_argument("--honeyfs", help="Cowrie honeyfs folder (cowrie-install)")
    parser.add_argument("--state-dir", default="/var/lib/trap/cowrie", help="manifest and fs.pickle backups")
    parser.add_argument("--restart-cmd", default="", help="command that restarts Cowrie after a change")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--decisions", help="Decision Engine decisions.jsonl (plan)")
    parser.add_argument("--eve", action="append", default=[], help="Suricata eve.json, repeatable (plan)")
    parser.add_argument("--web-log", action="append", default=[], help="synced rabbit-hole-web.jsonl (plan)")
    parser.add_argument("--plan-log", help="append each Jev planning result here (plan)")
    parser.add_argument("--push-command", default="", help="run after the plan file changes (plan)")
    parser.add_argument("--once", action="store_true", help="plan one round and exit (plan)")
    args = parser.parse_args(argv)
    config = load(args.config)
    if args.command == "check":
        problems = config.problems()
        print(json.dumps({"config": str(config.path), "enabled": config.enabled,
                          "problems": problems}, indent=2, ensure_ascii=False))
        return 1 if problems else 0
    if config.problems():
        print("config has problems; run the check command first", file=sys.stderr)
        return 1
    if args.command == "plan":
        from .planner import Planner, run_forever
        planner = Planner(config, args.decisions, args.eve, args.web_log,
                          Path(args.out) if args.out != "rabbit-hole-cowrie.zip" else None,
                          args.push_command, log_path=Path(args.plan_log) if args.plan_log else None)
        if args.once:
            print(json.dumps(planner.run_once(), ensure_ascii=False, default=str))
            return 0
        run_forever(planner)
        return 0
    if args.command == "serve":
        from .web import serve
        serve(config)
        return 0
    if args.command == "preview":
        faker = Faker(config.secret(), "web:" + args.session, config.organization)
        for scenario in config.selected("web") + config.selected("shell"):
            print(f"## {scenario.id} ({scenario.protocol}) - {scenario.title}")
            for node in sorted(scenario.nodes.values(), key=lambda n: (n.depth, n.path)):
                print(f"  depth {node.depth}  {node.kind:<10} {node.path}  -> {', '.join(node.next) or '-'}")
        return 0
    if args.command == "cowrie-install":
        if not args.fs_pickle or not args.honeyfs:
            print("--fs-pickle and --honeyfs are required", file=sys.stderr)
            return 2
        from .cowrie_install import install, restart
        result = install(config, Path(args.fs_pickle), Path(args.honeyfs), Path(args.state_dir), args.force)
        if result["changed"]:
            result["restarted"] = restart(args.restart_cmd)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result.get("restarted", True) else 1
    Path(args.out).write_bytes(shell.export_bundle(config))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
