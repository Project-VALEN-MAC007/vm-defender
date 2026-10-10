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


def raw_event(flow_id=1, source="192.0.2.20", protocol="http", sid=2006446, severity=1,
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
    def test_maximum_risk_keeps_redirecting_each_protocol(self):
        now = datetime(2026, 8, 4, 20, tzinfo=timezone.utc)
        for protocol, port in (("http", 80), ("ssh", 22), ("telnet", 23)):
            with self.subTest(protocol=protocol):
                engine = RiskEngine({"monitor": 15, "redirect": 40}, 1, 1800, lambda: now)
                for flow_id in range(1, 8):
                    decision = engine.decide(Event.from_eve(raw_event(
                        flow_id=flow_id, protocol=protocol, dest_port=port)))
                self.assertEqual(decision.risk_score, 100)
                self.assertEqual(decision.action, "redirect_web" if protocol == "http" else "redirect_" + protocol)

    def test_rabbit_hole_profile_renders(self):
        rendered = NginxMapAdapter(Path("unused")).render({"192.0.2.20": "rabbithole"})
        self.assertIn("192.0.2.20 rabbithole;", rendered)

    def test_dedup_and_cross_protocol_history(self):
        now = datetime(2026, 8, 4, 20, tzinfo=timezone.utc)
        engine = RiskEngine({"monitor":15,"redirect":40}, 1, 1800, lambda: now)
        scan = Event.from_eve(raw_event(protocol="http", sid=2009359, severity=3))
        self.assertIsNotNone(engine.decide(scan))
        self.assertIsNone(engine.decide(scan))
        decision = engine.decide(Event.from_eve(raw_event(flow_id=2, protocol="http", severity=3)))
        self.assertEqual(decision.action, "redirect_web")
        self.assertIn("active_scan_history", decision.reason)

    def test_decay(self):
        times = [datetime(2026, 8, 4, 20, tzinfo=timezone.utc)]
        engine = RiskEngine({"monitor":15,"redirect":40}, 10, 1800, lambda: times[0])
        engine.decide(Event.from_eve(raw_event()))
        before = engine.states["192.0.2.20"].score
        times[0] += timedelta(minutes=2)
        engine.decide(Event.from_eve(raw_event(flow_id=2, severity=3)))
        self.assertLess(engine.states["192.0.2.20"].score, before + 17)

    def test_telnet_redirect_from_metadata_and_port(self):
        now = datetime(2026, 8, 4, 20, tzinfo=timezone.utc)
        engine = RiskEngine({"monitor":15,"redirect":40}, 1, 1800, lambda: now)
        event_raw = raw_event(protocol="tcp", sid=2101251, severity=1, dest_port=50000)
        event_raw.update(src_ip="192.0.2.10", src_port=23, dest_ip="192.0.2.20")
        event = Event.from_eve(event_raw)
        self.assertEqual(event.protocol, "telnet")
        self.assertEqual(event.source_ip, "192.0.2.20")
        self.assertEqual(event.destination_port, 23)
        decision = engine.decide(event)
        self.assertEqual(decision.action, "redirect_telnet")
        self.assertEqual(decision.profile, "cowrie")

    def test_telnet_response_requires_server_port_and_client_ip(self):
        for sid in (2100492, 2101251):
            record = raw_event(protocol="tcp", sid=sid, dest_port=50000)
            record.update(src_port=80, dest_ip="192.0.2.20")
            with self.assertRaises(ValueError):
                Event.from_eve(record)
            record.update(src_port=23, dest_ip="")
            with self.assertRaises(ValueError):
                Event.from_eve(record)


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
                "nginx_map_path":"m","thresholds":{"monitor":15,"redirect":40},
                "bind_host":"0.0.0.0"}))
            with self.assertRaises(ValueError):
                load_settings(path)


class EngineIntegrationTests(unittest.TestCase):
    def test_apply_mode_constructs_with_nginx_validator(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(root/"eve", root/"checkpoint", root/"audit", root/"map", False, 1, 1800,
                                {"monitor":15,"redirect":40})
            engine = DecisionEngine(settings)
            self.assertFalse(engine.nginx.dry_run)

    def test_restart_does_not_reprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); eve = root/"eve.json"
            eve.write_text(json.dumps(raw_event()) + "\n")
            settings = Settings(eve, root/"checkpoint", root/"audit", root/"map", True, 1, 1800,
                                {"monitor":15,"redirect":40})
            self.assertEqual(len(DecisionEngine(settings).run_once()), 1)
            self.assertEqual(len(DecisionEngine(settings).run_once()), 0)

    def test_telnet_decision_uses_telnet_nft_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); eve = root/"eve.json"
            record = raw_event(protocol="tcp", sid=2101251, severity=1, dest_port=50000)
            record.update(src_ip="192.0.2.10", src_port=23, dest_ip="192.0.2.20")
            eve.write_text(json.dumps(record) + "\n")
            settings = Settings(eve, root/"checkpoint", root/"audit", root/"map", True, 1, 1800,
                                {"monitor":15,"redirect":40})
            decisions = DecisionEngine(settings).run_once()
            self.assertEqual(decisions[0]["action"], "redirect_telnet")
            self.assertIn("telnet_redirect", decisions[0]["adapter_command"])

    def test_failed_adapter_does_not_checkpoint_event(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); eve = root/"eve.json"; checkpoint = root/"checkpoint"
            eve.write_text(json.dumps(raw_event(protocol="http", severity=1)) + "\n")
            settings = Settings(eve, checkpoint, root/"audit", root/"map", True, 1, 1800,
                                {"monitor":15,"redirect":40})
            engine = DecisionEngine(settings)
            engine.reconcile_web_redirects()
            engine.nginx.update = lambda entries: (_ for _ in ()).throw(RuntimeError("reload failed"))
            self.assertEqual(engine.run_once(), [])
            self.assertFalse(checkpoint.exists())
            engine.nginx.update = lambda entries: "ok"
            self.assertEqual(len(engine.run_once()), 1)
            self.assertTrue(checkpoint.exists())

    def test_web_redirect_state_expires_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); eve = root/"eve.json"; map_path = root/"redirect.map"
            eve.write_text(json.dumps(raw_event(protocol="http", severity=1)) + "\n")
            settings = Settings(eve, root/"checkpoint", root/"audit", map_path, False, 1, 1800,
                                {"monitor":15,"redirect":40})
            engine = DecisionEngine(settings)
            rendered = []
            engine.nginx.update = lambda entries: rendered.append(dict(entries)) or "ok"
            self.assertEqual(len(engine.run_once()), 1)
            self.assertTrue(engine.web_state_path.exists())
            restarted = DecisionEngine(settings)
            restarted.nginx.update = lambda entries: rendered.append(dict(entries)) or "ok"
            self.assertIn("192.0.2.20", restarted._active_web_profiles())
            restarted.web_entries["192.0.2.20"]["expiry"] = "2000-01-01T00:00:00+00:00"
            restarted.reconcile_web_redirects()
            self.assertEqual(rendered[-1], {})


if __name__ == "__main__": unittest.main()


class EngineResilienceTests(unittest.TestCase):
    def settings(self, root, eve, dry_run=True):
        return Settings(eve, root/"checkpoint", root/"audit", root/"map", dry_run, 1, 1800,
                        {"monitor": 15, "redirect": 40})

    def test_unreadable_alert_is_skipped_not_stuck(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); eve = root/"eve.json"
            bad = raw_event(protocol="tcp", sid=2101251, dest_port=50000)
            bad.update(src_ip="192.0.2.10", src_port=80, dest_ip="192.0.2.20")
            good = raw_event(flow_id=2, source="192.0.2.9")
            eve.write_text(json.dumps(bad) + "\n" + json.dumps(good) + "\n")
            decisions = DecisionEngine(self.settings(root, eve)).run_once()
            self.assertEqual([d["source_ip"] for d in decisions], ["192.0.2.9"])
            self.assertIn('"reason": "unreadable_alert"', (root/"audit").read_text())

    def test_adapter_failure_retries_then_moves_on(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); eve = root/"eve.json"
            eve.write_text(json.dumps(raw_event(protocol="http", severity=1)) + "\n"
                           + json.dumps(raw_event(flow_id=2, source="192.0.2.9", protocol="http", severity=1)) + "\n")
            engine = DecisionEngine(self.settings(root, eve))
            engine.reconcile_web_redirects()
            calls = []
            def update(entries):
                calls.append(dict(entries))
                if "192.0.2.20" in entries:
                    raise RuntimeError("reload failed")
                return "ok"
            engine.nginx.update = update
            self.assertEqual(engine.run_once(), [])
            self.assertEqual(engine.run_once(), [])
            result = engine.run_once()
            self.assertEqual([d["source_ip"] for d in result], ["192.0.2.9"])
            self.assertIn('"reason": "adapter_failed"', (root/"audit").read_text())

    def test_ipv6_shell_attacker_is_monitored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); eve = root/"eve.json"
            eve.write_text(json.dumps(raw_event(source="2001:db8::5", protocol="ssh", dest_port=22, severity=1)) + "\n"
                           + json.dumps(raw_event(flow_id=2, source="2001:db8::5", protocol="ssh", dest_port=22, severity=1)) + "\n")
            decisions = DecisionEngine(self.settings(root, eve)).run_once()
            last = decisions[-1]
            self.assertEqual(last["action"], "monitor")
            self.assertNotIn("adapter_command", last)
            self.assertIn("ipv6_shell_redirect_unsupported:monitor", last["reason"])

    def test_nft_rejects_ipv6_redirect_sets(self):
        adapter = NftSetAdapter("inet", "adaptive_defender", True)
        with self.assertRaises(ValueError):
            adapter.add("ssh_redirect", "2001:db8::5", 60)
        with self.assertRaises(ValueError):
            adapter.add("unsupported_set", "192.0.2.5", 60)
