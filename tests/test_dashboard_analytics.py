from datetime import datetime, timezone
import unittest

from defender.dashboard.app import analytics, search_logs


class DashboardAnalyticsTests(unittest.TestCase):
    def test_window_counts_full_snapshot_and_ignores_undated_rows(self):
        now = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
        alerts = [
            {"timestamp": "2026-09-30T11:00:00Z", "src_ip": "192.0.2.1",
             "app_proto": "http", "severity": 1},
            {"timestamp": "2026-09-30T10:00:00+00:00", "src_ip": "192.0.2.1",
             "app_proto": "http", "severity": 2},
            {"timestamp": "2026-09-28T10:00:00Z", "src_ip": "192.0.2.2",
             "app_proto": "ssh", "severity": 3},
            {"timestamp": None, "src_ip": "192.0.2.3", "severity": 1},
        ]
        decisions = [
            {"start_time": "2026-09-30T11:00:00Z", "action": "redirect_web"},
            {"start_time": "2026-09-30T10:00:00Z", "action": "allow"},
            {"start_time": "2026-09-28T10:00:00Z", "action": "redirect_ssh"},
        ]
        day = analytics(alerts, decisions, "24h", now)
        self.assertEqual((day["total_alerts"], day["unique_source_ips"],
                          day["high_severity_alerts"]), (2, 1, 1))
        self.assertEqual(day["destinations"], {"real": 1, "honeypot": 1})
        self.assertEqual(len(day["trend"]), 25)
        self.assertEqual(sum(item["count"] for item in day["trend"]), 2)
        week = analytics(alerts, decisions, "7d", now)
        self.assertEqual(week["total_alerts"], 3)
        self.assertEqual(week["destinations"]["honeypot"], 2)
        self.assertFalse(week["honeypot_telemetry_available"])

    def test_rejects_unsupported_window(self):
        with self.assertRaises(ValueError):
            analytics([], [], "999d")

    def test_log_search_filters_before_pagination(self):
        alerts = [{"timestamp": "2026-09-30T11:00:00Z", "src_ip": "192.0.2.1",
                   "app_proto": "HTTP", "severity": 1, "signature": "probe"},
                  {"timestamp": "2026-09-30T10:00:00Z", "src_ip": "192.0.2.2",
                   "app_proto": "SSH", "severity": 3, "signature": "login"}]
        decisions = [{"start_time": "2026-09-30T11:10:00Z", "source_ip": "192.0.2.1",
                      "protocol": "http", "action": "redirect_web", "reason": "risk"}]
        result = search_logs(alerts, decisions, {"source": ["192.0.2.1"], "limit": ["1"]})
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["items"][0]["type"], "decision")
        result = search_logs(alerts, decisions, {"severity": ["1"],
                                                 "from": ["2026-09-30T10:30:00Z"]})
        self.assertEqual([row["summary"] for row in result["items"]], ["probe"])
        with self.assertRaises(ValueError):
            search_logs(alerts, decisions, {"from": ["not-a-date"]})
