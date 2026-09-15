from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
from typing import Callable


def append_registry(path: Path, payload: dict) -> None:
    allowed = {"candidate", "approved", "rejected", "deployed", "rolled_back"}
    if payload.get("status") not in allowed:
        raise ValueError("invalid rule status")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, sort_keys=True) + "\n")


def staged_deploy(candidate: dict, active_rules: Path, backup_dir: Path, registry: Path,
                  syntax_test: Callable[[Path], bool], reload_service: Callable[[], bool],
                  health_check: Callable[[], bool], dry_run: bool = True) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = {"rule_id": candidate["rule_id"], "version": candidate["version"],
            "timestamp": now, "reviewer": candidate["reviewer"],
            "evidence": candidate["evidence"]}
    append_registry(registry, {**base, "status": "approved", "reason": "five validation gates passed"})
    if dry_run:
        return {**base, "status": "approved", "deploy_performed": False}
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / f"local.rules.{now}.bak"
    if active_rules.exists():
        shutil.copy2(active_rules, backup)
        current = active_rules.read_text(encoding="utf-8")
    else:
        current = ""
        backup.write_text("", encoding="utf-8")
    staging = active_rules.with_suffix(active_rules.suffix + ".staging")
    staging.write_text(current.rstrip() + "\n" + candidate["rule"].strip() + "\n", encoding="utf-8")
    try:
        if not syntax_test(staging):
            raise RuntimeError("suricata syntax test failed")
        os.replace(staging, active_rules)
        if not reload_service() or not health_check():
            raise RuntimeError("reload or health check failed")
        result = {**base, "status": "deployed", "backup": str(backup), "deploy_performed": True}
        append_registry(registry, {**result, "reason": "activate/reload/health passed"})
        return result
    except Exception as exc:
        if staging.exists():
            staging.unlink()
        shutil.copy2(backup, active_rules)
        reload_service()
        result = {**base, "status": "rolled_back", "backup": str(backup),
                  "deploy_performed": True, "reason": str(exc)}
        append_registry(registry, result)
        return result
