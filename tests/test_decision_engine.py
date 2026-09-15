from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest

from defender.decision_engine.adaptive_defender.adapters import NftSetAdapter, NginxMapAdapter
from defender.decision_engine.adaptive_defender.config import Settings, load_settings
from defender.decision_engine.adaptive_defender.engine import DecisionEngine
from defender.decision_engine.adaptive_defender.models import Event
from defender.decision_engine.adaptive_defender.reader import EveReader
from defender.decision_engine.adaptive_defender.risk import RiskEngine


def raw_event(flow_id=1, source="192.0.2.20", protocol="http", sid=2200001, severity=1,
              dest_port=80, metadata=None):
    alert = {"signature_id": sid, "signature": "test", "severity": severity}
    if metadata is not None:
        alert["metadata"] = metadata
    return {"timestamp": "2026-08-04T19:40:00+00:00", "flow_id": flow_id,
            "event_type": "alert", "src_ip": source, "dest_port": dest_port,
            "app_proto": protocol, "alert": alert}


class ReaderTests(unittest.TestCase):
    def test_checkpoint_and_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); eve = root/"eve.json"; checkpoint = root/"checkpoint.json"
            eve.write_text(json.dumps(raw_event()) + "\n")
            self.assertEqual(len(list(EveReader(eve, checkpoint).records())), 1)
            self.assertEqual(len(list(EveReader(eve, checkpoint).records())), 0)
            replacement = root/"rotated"
            replacement.write_text(json.dumps(raw_event(flow_id=2)) + "\n")
            os.replace(replacement, eve)
            self.assertEqual(len(list(EveReader(eve, checkpoint).records())), 1)


class RiskTests(unittest.TestCase):
    def test_dedup_and_cross_protocol_history(self):
        now = datetime(2026, 8, 4, 20, tzinfo=timezone.utc)
        engine = RiskEngine({"monitor":15,"redirect":40,"temporary_block":80}, 1, 1800, lambda: now)
        scan = Event.from_eve(raw_event(protocol="scan", sid=2200301, severity=3))
        self.assertIsNotNone(engine.decide(scan))
        self.assertIsNone(engine.decide(scan))
        decision = engine.decide(Event.from_eve(raw_event(flow_id=2, protocol="http", severity=3)))
        self.assertEqual(decision.action, "redirect_web")
        self.assertIn("active_scan_history", decision.reason)

    def test_decay(self):
        times = [datetime(2026, 8, 4, 20, tzinfo=timezone.utc)]
        engine = RiskEngine({"monitor":15,"redirect":40,"temporary_block":80}, 10, 1800, lambda: times[0])
        engine.decide(Event.from_eve(raw_event()))
        before = engine.states["192.0.2.20"].score
        times[0] += timedelta(minutes=2)
        engine.decide(Event.from_eve(raw_event(flow_id=2, severity=3)))
        self.assertLess(engine.states["192.0.2.20"].score, before + 17)

    def test_telnet_redirect_from_metadata_and_port(self):
        now = datetime(2026, 8, 4, 20, tzinfo=timezone.utc)
        engine = RiskEngine({"monitor":15,"redirect":40,"temporary_block":80}, 1, 1800, lambda: now)
        event = Event.from_eve(raw_event(protocol="tcp", sid=2200203, severity=1,
                                         dest_port=23, metadata={"protocol": ["telnet"]}))
        self.assertEqual(event.protocol, "telnet")
        decision = engine.decide(event)
        self.assertEqual(decision.action, "redirect_telnet")
        self.assertEqual(decision.profile, "telnet")


class AdapterAndConfigTests(unittest.TestCase):
    def test_map_and_nft_dry_run(self):
        rendered = NginxMapAdapter(Path("unused"), True).update({"192.0.2.20":"wordpress"})
        self.assertIn("192.0.2.20 wordpress;", rendered)
        command = NftSetAdapter("inet", "adaptive_defender", True).add("ssh_redirect", "192.0.2.30", 60)
        self.assertEqual(command[0], "nft")
        telnet_command = NftSetAdapter("inet", "adaptive_defender", True).add("telnet_redirect", "192.0.2.31", 60)
        self.assertIn("telnet_redirect", telnet_command)
        with self.assertRaises(ValueError):
            NginxMapAdapter(Path("unused"), True).update({"not-an-ip":"real"})

    def test_map_validation_failure_restores_previous_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"redirect.map"; path.write_text("default real;\n")
            adapter = NginxMapAdapter(path, False, lambda candidate: False)
            with self.assertRaises(RuntimeError):
                adapter.update({"192.0.2.20":"wordpress"})
            self.assertEqual(path.read_text(), "default real;\n")

    def test_map_reload_failure_rolls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"redirect.map"; path.write_text("default real;\n")
            adapter = NginxMapAdapter(path, False, lambda candidate: True, lambda: False)
            with self.assertRaises(RuntimeError):
                adapter.update({"192.0.2.20":"wordpress"})
            self.assertEqual(path.read_text(), "default real;\n")

    def test_map_reload_success_keeps_new_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"redirect.map"; path.write_text("default real;\n")
            adapter = NginxMapAdapter(path, False, lambda candidate: True, lambda: True)
            adapter.update({"192.0.2.20":"wordpress"})
            self.assertIn("192.0.2.20 wordpress;", path.read_text())

    def test_config_rejects_non_loopback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"bad.json"
            path.write_text(json.dumps({"eve_path":"e","checkpoint_path":"c","audit_path":"a",
                "nginx_map_path":"m","thresholds":{"monitor":15,"redirect":40,"temporary_block":80},
                "bind_host":"0.0.0.0"}))
            with self.assertRaises(ValueError):
                load_settings(path)


class EngineIntegrationTests(unittest.TestCase):
    def test_apply_mode_constructs_with_nginx_validator(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(root/"eve", root/"checkpoint", root/"audit", root/"map", False, 1, 1800,
                                {"monitor":15,"redirect":40,"temporary_block":80})
            engine = DecisionEngine(settings)
            self.assertFalse(engine.nginx.dry_run)

    def test_restart_does_not_reprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); eve = root/"eve.json"
            eve.write_text(json.dumps(raw_event()) + "\n")
            settings = Settings(eve, root/"checkpoint", root/"audit", root/"map", True, 1, 1800,
                                {"monitor":15,"redirect":40,"temporary_block":80})
            self.assertEqual(len(DecisionEngine(settings).run_once()), 1)
            self.assertEqual(len(DecisionEngine(settings).run_once()), 0)

    def test_telnet_decision_uses_telnet_nft_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); eve = root/"eve.json"
            eve.write_text(json.dumps(raw_event(protocol="tcp", sid=2200203, severity=1,
                                                dest_port=23, metadata={"protocol": ["telnet"]})) + "\n")
            settings = Settings(eve, root/"checkpoint", root/"audit", root/"map", True, 1, 1800,
                                {"monitor":15,"redirect":40,"temporary_block":80})
            decisions = DecisionEngine(settings).run_once()
            self.assertEqual(decisions[0]["action"], "redirect_telnet")
            self.assertIn("telnet_redirect", decisions[0]["adapter_command"])


if __name__ == "__main__": unittest.main()
