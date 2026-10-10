"""Regression tests for the four items that failed the 2026-10-10 E2E run."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from defender.dashboard.scope import threshold_config
from defender.decision_engine.adaptive_defender.config import load_settings
from defender.decision_engine.adaptive_defender.engine import DecisionEngine
from defender.decision_engine.adaptive_defender.models import Event
from defender.decision_engine.adaptive_defender.risk import RiskEngine

ROOT = Path(__file__).resolve().parents[1]


def raw_event(flow_id=1, source="192.0.2.30", protocol="http", sid=2006446, severity=1, dest_port=80):
    return {"timestamp": "2026-10-10T07:00:00+00:00", "flow_id": flow_id, "event_type": "alert",
            "src_ip": source, "dest_port": dest_port, "app_proto": protocol,
            "alert": {"signature_id": sid, "signature": "test", "severity": severity}}


def engine_config(root, **extra):
    raw = json.loads((ROOT / "defender/decision_engine/config/lab.json").read_text(encoding="utf-8"))
    for field in ("eve_path", "checkpoint_path", "audit_path", "nginx_map_path"):
        raw[field] = str(root / (field + ".json"))
    Path(raw["eve_path"]).write_text("", encoding="utf-8")
    raw.update(extra)
    path = root / "live.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


class ScanOnlyPolicyTests(unittest.TestCase):
    """FAIL #2: network scans must stay alert-only at any threshold."""

    def setUp(self):
        self.now = datetime(2026, 10, 10, 7, tzinfo=timezone.utc)

    def test_masscan_never_redirects_even_with_low_threshold(self):
        engine = RiskEngine({"monitor": 5, "redirect": 10}, 1, 1800, lambda: self.now)
        for flow_id in range(1, 6):
            decision = engine.decide(Event.from_eve(raw_event(flow_id=flow_id, sid=2017616, severity=1)))
            self.assertEqual(decision.action, "monitor")
            self.assertEqual(decision.profile, "real")
            self.assertIn("scan_only_policy:monitor", decision.reason)
        self.assertEqual(decision.risk_score, 100)

    def test_scan_score_still_counts_for_the_next_attack(self):
        engine = RiskEngine({"monitor": 15, "redirect": 40}, 1, 1800, lambda: self.now)
        engine.decide(Event.from_eve(raw_event(flow_id=1, sid=2017616, severity=1)))
        decision = engine.decide(Event.from_eve(raw_event(flow_id=2, sid=2101071, severity=3)))
        self.assertEqual(decision.action, "redirect_web")

    def test_ssh_frequent_connections_still_redirect(self):
        # The thesis redirects SSH on frequent connections (2001219); it is not scan-only.
        engine = RiskEngine({"monitor": 15, "redirect": 30}, 1, 1800, lambda: self.now)
        decision = engine.decide(Event.from_eve(raw_event(protocol="ssh", sid=2001219, severity=2, dest_port=22)))
        self.assertEqual(decision.action, "redirect_ssh")

    def test_scan_only_list_is_configurable_and_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = load_settings(engine_config(root, scan_only_signatures=[2017616, 2001219]))
            self.assertEqual(settings.scan_only_signatures, frozenset({2017616, 2001219}))
            for bad in ("2017616", [True], [-1]):
                with self.assertRaises(ValueError):
                    load_settings(engine_config(root, scan_only_signatures=bad))


class ThresholdFileTests(unittest.TestCase):
    """FAIL #4: the Dashboard writes thresholds outside read-only /etc."""

    def test_dashboard_writes_override_and_leaves_engine_config_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            override = root / "state" / "thresholds.json"
            config = engine_config(root, thresholds_path=str(override))
            before = config.read_text(encoding="utf-8")
            self.assertEqual(threshold_config(config), {"monitor": 15, "redirect": 40})
            self.assertEqual(threshold_config(config, {"monitor": 10, "redirect": 30}), {"monitor": 10.0, "redirect": 30.0})
            self.assertEqual(config.read_text(encoding="utf-8"), before)
            self.assertEqual(json.loads(override.read_text())["thresholds"], {"monitor": 10.0, "redirect": 30.0})
            self.assertEqual(threshold_config(config), {"monitor": 10.0, "redirect": 30.0})
            self.assertEqual(load_settings(config).thresholds, {"monitor": 10.0, "redirect": 30.0})

    def test_engine_picks_up_override_without_losing_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            override = root / "thresholds.json"
            config = engine_config(root, thresholds_path=str(override))
            engine = DecisionEngine(load_settings(config))
            states = engine.risk.states
            threshold_config(config, {"monitor": 12, "redirect": 39})
            engine.run_once()
            self.assertEqual(engine.risk.thresholds, {"monitor": 12.0, "redirect": 39.0})
            self.assertIs(engine.risk.states, states)

    def test_bad_override_keeps_last_good_thresholds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            override = root / "thresholds.json"
            config = engine_config(root, thresholds_path=str(override))
            engine = DecisionEngine(load_settings(config))
            override.write_text(json.dumps({"thresholds": {"monitor": 50, "redirect": 20}}))
            engine.run_once()  # must not raise
            self.assertEqual(engine.risk.thresholds, {"monitor": 15.0, "redirect": 40.0})

    def test_without_override_path_lab_mode_edits_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config = engine_config(Path(directory))
            threshold_config(config, {"monitor": 11, "redirect": 33})
            self.assertEqual(json.loads(config.read_text())["thresholds"], {"monitor": 11.0, "redirect": 33.0})


class LibsshRuleTests(unittest.TestCase):
    """FAIL #1: SID 2006546 matches the parsed SSH client software."""

    def test_rule_uses_ssh_software_buffer(self):
        rules = (ROOT / "defender/suricata/rules/et-open-selected.rules").read_text(encoding="utf-8")
        line = next(l for l in rules.splitlines() if "sid:2006546;" in l)
        self.assertIn('ssh.software; content:"libssh"; nocase;', line)
        self.assertNotIn('content:"SSH-"', line)
        self.assertIn("threshold: type both, count 5, seconds 30, track by_src;", line)
        self.assertEqual(sum("sid:" in l for l in rules.splitlines() if l.startswith("alert ")), 13)


class InstallScriptTests(unittest.TestCase):
    """FAIL #3: the rule apply helper and thresholds file get installed."""

    def test_install_script_covers_helper_and_thresholds(self):
        script = (ROOT / "deploy/install-dashboard-helpers.sh").read_text(encoding="utf-8")
        for needle in ("trap-apply-rules.path", "systemctl enable --now trap-apply-rules.path",
                       "apply_dir", "thresholds_path", "scan_only_signatures", "suricata/apply_rules.py"):
            self.assertIn(needle, script)


if __name__ == "__main__":
    unittest.main()
