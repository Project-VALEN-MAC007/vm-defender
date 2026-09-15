from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import tempfile
import time


SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")


class ValidationError(ValueError):
    pass


def load_candidate(path: Path) -> dict:
    candidate = json.loads(path.read_text(encoding="utf-8"))
    required = {"rule_id", "version", "evidence", "confidence", "reviewer", "rule", "expected_sid"}
    missing = required - set(candidate)
    if missing:
        raise ValidationError(f"missing metadata: {sorted(missing)}")
    if candidate.get("status") not in {None, "candidate"}:
        raise ValidationError("incoming status must be candidate")
    if not 0 <= float(candidate["confidence"]) <= 1:
        raise ValidationError("confidence must be 0..1")
    return candidate


def syntax_gate(candidate: dict) -> dict:
    rule = candidate["rule"].strip()
    matches = SID.findall(rule)
    if not rule.startswith("alert ") or len(matches) != 1 or not rule.endswith(")"):
        raise ValidationError("rule failed structural syntax gate")
    if int(matches[0]) != int(candidate["expected_sid"]):
        raise ValidationError("expected_sid does not match rule")
    if not all(token in rule for token in ("msg:", "classtype:", "metadata:severity", "threshold:")):
        raise ValidationError("required rule metadata is absent")
    return {"gate": 1, "name": "syntax", "status": "passed", "sid": int(matches[0])}


def duplicate_gate(candidate: dict, deployed_rules: str) -> dict:
    sid = int(candidate["expected_sid"])
    existing = [int(value) for value in SID.findall(deployed_rules)]
    if sid in existing:
        raise ValidationError(f"duplicate SID {sid}")
    normalized = " ".join(candidate["rule"].split())
    if normalized in " ".join(deployed_rules.split()):
        raise ValidationError("exact overlapping rule")
    return {"gate": 2, "name": "duplicate_overlap", "status": "passed"}


def regression_gate(candidate: dict, baseline: list[dict]) -> dict:
    false_positives = sum(1 for row in baseline if not row["expected_malicious"] and row.get("candidate_alert", False))
    benign = sum(1 for row in baseline if not row["expected_malicious"])
    rate = false_positives / benign if benign else 0.0
    maximum = float(candidate.get("max_false_positive_rate", 0.05))
    if rate > maximum:
        raise ValidationError(f"false-positive rate {rate:.4f} exceeds {maximum:.4f}")
    return {"gate": 3, "name": "baseline_regression", "status": "passed", "false_positive_rate": rate}


def malicious_replay_gate(candidate: dict, baseline: list[dict]) -> dict:
    malicious = [row for row in baseline if row["expected_malicious"]]
    detected = sum(1 for row in malicious if row.get("candidate_alert", False))
    minimum = int(candidate.get("minimum_malicious_detections", 1))
    if detected < minimum:
        raise ValidationError("malicious replay did not meet detection gate")
    return {"gate": 4, "name": "malicious_replay", "status": "passed", "detected": detected}


def performance_gate(candidate: dict, elapsed_ms: float, baseline_count: int) -> dict:
    per_event = elapsed_ms / max(1, baseline_count)
    maximum = float(candidate.get("max_validation_ms_per_event", 10.0))
    if per_event > maximum:
        raise ValidationError("performance gate exceeded")
    return {"gate": 5, "name": "performance_false_positive", "status": "passed", "ms_per_event": per_event}


def validate(candidate_path: Path, deployed_path: Path, baseline_path: Path) -> dict:
    started = time.perf_counter()
    candidate = load_candidate(candidate_path)
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    deployed = deployed_path.read_text(encoding="utf-8") if deployed_path.exists() else ""
    gates = [syntax_gate(candidate), duplicate_gate(candidate, deployed),
             regression_gate(candidate, baseline), malicious_replay_gate(candidate, baseline)]
    gates.append(performance_gate(candidate, (time.perf_counter() - started) * 1000, len(baseline)))
    return {"rule_id": candidate["rule_id"], "version": candidate["version"],
            "status": "approved", "gates": gates, "deploy_performed": False}
