import json
from pathlib import Path
import tempfile
import unittest

from defender.dashboard.app import csv_export, live_status, summary
from defender.dashboard.metrics import calculate
from defender.validation.deploy import staged_deploy
from defender.validation.pipeline import ValidationError, validate
from defender.validation.readiness import assess

PROJECT = Path(__file__).resolve().parents[1]


class DashboardTests(unittest.TestCase):
    def test_summary_csv_metrics(self):
        rows = [{"action":"redirect_web","protocol":"http","source_ip":"192.0.2.20"}]
        self.assertEqual(summary(rows)["by_action"]["redirect_web"], 1)
        self.assertIn("source_ip", csv_export(rows))
        metrics = calculate(json.loads((PROJECT/"tests/fixtures/baseline.json").read_text()))
        self.assertEqual(metrics["detection_accuracy"], 1.0)
        self.assertEqual(metrics["false_positive_rate"], 0.0)
        self.assertIn("suricata", live_status())


class ValidationTests(unittest.TestCase):
    def test_five_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            deployed = Path(directory)/"deployed.rules"; deployed.write_text("")
            report = validate(PROJECT/"tests/fixtures/candidate.json", deployed,
                              PROJECT/"tests/fixtures/baseline.json")
            self.assertEqual(report["status"], "approved")
            self.assertEqual(len(report["gates"]), 5)
            self.assertFalse(report["deploy_performed"])

    def test_duplicate_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            deployed = Path(directory)/"deployed.rules"
            deployed.write_text("alert tcp any any -> any any (msg:\"x\"; sid:2200401; rev:1;)\n")
            with self.assertRaises(ValidationError):
                validate(PROJECT/"tests/fixtures/candidate.json", deployed,
                         PROJECT/"tests/fixtures/baseline.json")

    def test_failed_health_rolls_back(self):
        candidate = json.loads((PROJECT/"tests/fixtures/candidate.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); active = root/"local.rules"; active.write_text("original\n")
            result = staged_deploy(candidate, active, root/"backups", root/"registry.jsonl",
                                   lambda path: True, lambda: True, lambda: False, False)
            self.assertEqual(result["status"], "rolled_back")
            self.assertEqual(active.read_text(), "original\n")


if __name__ == "__main__": unittest.main()


class ReadinessTests(unittest.TestCase):
    def test_current_known_blockers_are_reported(self):
        def runner(command):
            class Result:
                returncode = 0
                stderr = ""
            result = Result()
            if command == ["ip", "-brief", "address"]:
                result.stdout = "lo UNKNOWN 127.0.0.1/8\nenp0s3 UP 10.0.2.15/24\n"
            elif command == ["systemctl", "is-active", "suricata"]:
                result.stdout = "active\n"
            elif command == ["systemctl", "is-active", "nginx"]:
                result.stdout = "inactive\n"
            else:
                result.stdout = ""
                result.returncode = 1
            return result

        report = assess(runner, lambda binary: "/usr/bin/" + binary if binary in {"suricata", "nft"} else None)
        checks = {item["name"]: item for item in report["checks"]}
        self.assertFalse(report["ready_for_live_deploy"])
        self.assertEqual(checks["lab_outer_interface"]["status"], "blocked")
        self.assertEqual(checks["lab_inner_interface"]["status"], "blocked")
        self.assertEqual(checks["deployment_gate"]["status"], "blocked")
        self.assertEqual(checks["binary_nginx"]["status"], "blocked")
        self.assertEqual(checks["service_suricata"]["status"], "passed")
