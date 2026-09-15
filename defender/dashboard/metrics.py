from __future__ import annotations


def calculate(rows: list[dict]) -> dict[str, float]:
    tp = sum(1 for row in rows if row["expected_malicious"] and row["detected"])
    tn = sum(1 for row in rows if not row["expected_malicious"] and not row["detected"])
    fp = sum(1 for row in rows if not row["expected_malicious"] and row["detected"])
    fn = sum(1 for row in rows if row["expected_malicious"] and not row["detected"])
    total = tp + tn + fp + fn
    benign = tn + fp
    return {
        "detection_accuracy": (tp + tn) / total if total else 0.0,
        "false_positive_rate": fp / benign if benign else 0.0,
        "decision_latency_ms": sum(row.get("decision_latency_ms", 0) for row in rows) / total if total else 0.0,
        "redirect_latency_ms": sum(row.get("redirect_latency_ms", 0) for row in rows) / total if total else 0.0,
    }
