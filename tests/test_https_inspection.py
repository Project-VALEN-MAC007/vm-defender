"""HTTPS detection: decrypted traffic is inspected on a loopback hop behind the
Nginx TLS edge, and alerts there are attributed to the real client only via the
header the edge sets (reported by Suricata as "xff")."""
from datetime import datetime, timezone
from pathlib import Path
import unittest

from defender.dashboard.data_store import alert_transform
from defender.decision_engine.adaptive_defender.models import Event
from defender.decision_engine.adaptive_defender.risk import RiskEngine

ROOT = Path(__file__).resolve().parents[1]


def alert(**over):
    raw = {"timestamp": "2026-10-11T05:00:00+00:00", "event_type": "alert",
           "src_ip": "127.0.0.2", "src_port": 40000, "dest_ip": "127.0.0.1",
           "dest_port": 18443, "proto": "TCP", "app_proto": "http", "flow_id": 1,
           "xff": "192.168.56.40", "in_iface": "lo",
           "alert": {"signature_id": 2008538, "severity": 2,
                     "signature": "ET SCAN Sqlmap SQL Injection Scan"}}
    raw.update(over)
    return raw


class EngineAttributionTests(unittest.TestCase):
    def test_suricata7_nested_alert_xff_is_attributed(self):
        raw = alert(); raw["alert"]["xff"] = raw.pop("xff")
        event = Event.from_eve(raw)
        self.assertEqual(event.source_ip, "192.168.56.40")
        self.assertEqual(event.protocol, "https")

    def test_loopback_alert_uses_client_header(self):
        event = Event.from_eve(alert())
        self.assertEqual(event.source_ip, "192.168.56.40")
        self.assertEqual(event.protocol, "https")
        self.assertEqual(event.destination_port, 443)

    def test_ambiguous_xff_list_is_rejected(self):
        with self.assertRaises(ValueError):
            Event.from_eve(alert(xff="10.9.9.9, 192.168.56.41"))

    def test_only_trusted_edge_on_loopback_can_attribute_client(self):
        for values in ({"src_ip": "127.0.0.3"}, {"in_iface": "trap-out"},
                       {"in_iface": None}, {"xff": "0.0.0.0"},
                       {"xff": "224.0.0.1"}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                Event.from_eve(alert(**values))

    def test_exact_inspection_destination_is_required(self):
        event = Event.from_eve(alert(dest_ip="127.0.0.3"))
        self.assertEqual(event.source_ip, "127.0.0.2")
        self.assertNotEqual(event.protocol, "https")

    def test_loopback_alert_without_client_is_rejected(self):
        raw = alert(); raw.pop("xff")
        with self.assertRaises(ValueError):
            Event.from_eve(raw)
        with self.assertRaises(ValueError):
            Event.from_eve(alert(xff="127.0.0.2"))

    def test_forged_header_on_outer_interface_is_ignored(self):
        # A client can send any header on plain HTTP; outside the loopback hop
        # it must never change who gets redirected.
        event = Event.from_eve(alert(src_ip="192.168.56.42", dest_ip="192.168.56.10",
                                     dest_port=80, xff="192.168.56.99"))
        self.assertEqual(event.source_ip, "192.168.56.42")
        self.assertEqual(event.protocol, "http")

    def test_other_loopback_ports_are_not_trusted(self):
        event = Event.from_eve(alert(dest_port=8080))
        self.assertEqual(event.source_ip, "127.0.0.2")

    def test_https_alert_redirects_to_web_honeypot(self):
        now = datetime(2026, 10, 11, 5, tzinfo=timezone.utc)
        engine = RiskEngine({"monitor": 15, "redirect": 40}, 1, 120, lambda: now,
                            web_profile="rabbithole")
        decision = engine.decide(Event.from_eve(alert()))
        self.assertEqual(decision.source_ip, "192.168.56.40")
        self.assertEqual(decision.action, "redirect_web")
        self.assertEqual(decision.profile, "rabbithole")


class DashboardTests(unittest.TestCase):
    def test_suricata7_nested_alert_xff_is_displayed(self):
        raw = alert(); raw["alert"]["xff"] = raw.pop("xff")
        row = alert_transform(raw, Path("eve.json"))
        self.assertEqual(row["src_ip"], "192.168.56.40")
        self.assertEqual(row["app_proto"], "https")

    def test_invalid_hop_alert_does_not_appear_under_forged_or_loopback_ip(self):
        for values in ({"src_ip": "127.0.0.3"}, {"in_iface": "trap-out"},
                       {"xff": "bad"}, {"xff": "127.0.0.2"}):
            with self.subTest(values=values):
                self.assertIsNone(alert_transform(alert(**values), Path("eve.json")))

    def test_dashboard_shows_real_client_for_https_alert(self):
        row = alert_transform(alert(), Path("eve.json"))
        self.assertEqual(row["src_ip"], "192.168.56.40")
        self.assertEqual(row["app_proto"], "https")
        self.assertEqual(row["dest_port"], 443)

    def test_dashboard_ignores_header_outside_hop(self):
        row = alert_transform(alert(src_ip="192.168.56.42", dest_ip="192.168.56.10",
                                    dest_port=80, xff="192.168.56.99"), Path("eve.json"))
        self.assertEqual(row["src_ip"], "192.168.56.42")


class NginxTemplateTests(unittest.TestCase):
    def setUp(self):
        self.t = (ROOT / "defender/nginx/adaptive-honeypot.conf.template").read_text(encoding="utf-8")

    def test_tls_edge_feeds_loopback_hop(self):
        edge = self.t[self.t.index("listen __OUTER_IP__:443 ssl;"):self.t.index("listen 127.0.0.1:18443;")]
        self.assertIn("proxy_set_header X-Trap-Client-IP $remote_addr;", edge)
        self.assertIn("proxy_bind 127.0.0.2;", edge)
        self.assertIn("proxy_pass http://127.0.0.1:18443;", edge)
        self.assertNotIn("$adaptive_backend", edge)

    def test_hop_trusts_only_edge_and_strips_header(self):
        hop = self.t[self.t.index("listen 127.0.0.1:18443;"):]
        self.assertIn("set_real_ip_from 127.0.0.2;", hop)
        self.assertIn("real_ip_header X-Trap-Client-IP;", hop)
        self.assertIn('proxy_set_header X-Trap-Client-IP "";', hop)
        self.assertIn("proxy_set_header X-Forwarded-Proto https;", hop)
        self.assertIn("proxy_pass $adaptive_backend;", hop)
        self.assertIn("access_log /var/log/nginx/adaptive_access.json adaptive_json_tls;", hop)

    def test_http_listener_unchanged(self):
        http = self.t[self.t.index("listen __OUTER_IP__:80;"):self.t.index("# HTTPS (port 443).")]
        self.assertIn("proxy_pass $adaptive_backend;", http)
        self.assertNotIn("18443", http)


if __name__ == "__main__":
    unittest.main()
