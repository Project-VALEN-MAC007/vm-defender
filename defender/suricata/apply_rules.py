"""Install rules edited in the TRAP Dashboard into Suricata (runs as root).

Started by trap-apply-rules.path whenever the Dashboard writes
<apply_dir>/request. The Dashboard itself never gets write access to
/etc/suricata; it only drops pending.rules into apply_dir.

Steps: suricata -T on the pending file -> back up the active file -> install ->
reload Suricata -> health check. Any failure restores the previous file and is
reported in result.json, which the Dashboard shows on the rules page.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Callable, Sequence

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess"]


def _run(command: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(list(command), capture_output=True, text=True, timeout=120, check=False)


def _write_result(path: Path, payload: dict) -> None:
    payload = {**payload, "time": datetime.now(timezone.utc).isoformat()}
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def _tail(text: str, lines: int = 8) -> str:
    return "\n".join((text or "").strip().splitlines()[-lines:])


def _reload(run: Runner) -> bool:
    if run(["suricatasc", "-c", "reload-rules"]).returncode == 0:
        return True
    return run(["systemctl", "reload", "suricata"]).returncode == 0


def apply(pending: Path, active: Path, suricata_config: Path, result: Path,
          run: Runner = _run) -> dict:
    if not pending.exists():
        return {"state": "idle"}
    text = pending.read_text(encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    test = run(["suricata", "-T", "-c", str(suricata_config), "-S", str(pending)])
    if test.returncode != 0:
        outcome = {"state": "failed", "step": "syntax_test", "sha256": digest,
                   "detail": _tail(test.stderr or test.stdout)}
        _write_result(result, outcome)
        return outcome
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = active.with_name(active.name + f".{stamp}.bak")
    if active.exists():
        shutil.copy2(active, backup)
    staging = active.with_name("." + active.name + ".staging")
    staging.write_text(text, encoding="utf-8")
    os.chmod(staging, 0o644)
    os.replace(staging, active)
    if _reload(run) and run(["systemctl", "is-active", "--quiet", "suricata"]).returncode == 0:
        pending.unlink()
        outcome = {"state": "applied", "sha256": digest, "backup": str(backup)}
        _write_result(result, outcome)
        return outcome
    if backup.exists():
        shutil.copy2(backup, active)
    _reload(run)
    outcome = {"state": "failed", "step": "reload", "sha256": digest,
               "detail": "Suricata did not reload the new rules; the previous file was restored"}
    _write_result(result, outcome)
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apply-dir", default="/var/lib/trap/rules")
    parser.add_argument("--active", default="/etc/suricata/rules/et-open-selected.rules")
    parser.add_argument("--suricata-config", default="/etc/suricata/suricata.yaml")
    args = parser.parse_args()
    apply_dir = Path(args.apply_dir)
    outcome = apply(apply_dir / "pending.rules", Path(args.active), Path(args.suricata_config),
                    apply_dir / "result.json")
    print(json.dumps(outcome, ensure_ascii=False))
    return 0 if outcome["state"] in {"applied", "idle"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
