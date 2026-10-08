"""Command line for Rabbit Hole.

  python -m defender.rabbit_hole check  --config config/rabbit-hole.json
  python -m defender.rabbit_hole serve  --config config/rabbit-hole.json
  python -m defender.rabbit_hole preview --config config/rabbit-hole.json [--session demo]
  python -m defender.rabbit_hole cowrie-bundle --config config/rabbit-hole.json --out bundle.zip
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
    parser.add_argument("command", choices=["check", "serve", "preview", "cowrie-bundle"])
    parser.add_argument("--config", default="config/rabbit-hole.json")
    parser.add_argument("--session", default="preview")
    parser.add_argument("--out", default="rabbit-hole-cowrie.zip")
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
    Path(args.out).write_bytes(shell.export_bundle(config))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
