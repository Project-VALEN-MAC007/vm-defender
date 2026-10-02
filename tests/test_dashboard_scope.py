from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch

import test_dashboard_security as fixtures
from defender.dashboard.app import handler_factory, read_rules, analytics
from defender.dashboard.scope import sessions_from_events, honeypot_transform, RuleStore, report_csv
from defender.dashboard.security import UserStore, totp_code


class DashboardScopeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.DashboardApiSecurityTests()
        self.fixture.setUp()
        self.fixture.server.shutdown()
        self.fixture.server.server_close()
        self.fixture.thread.join()
        root = self.fixture.paths["users"].parent
        self.engine = root / "engine.json"
        self.engine.write_text(json.dumps({"thresholds": {"monitor": 15, "redirect": 40, "temporary_block": 80}}))
        self.honeypot = root / "honeypot.jsonl"
        self.settings = replace(self.fixture.settings, demo_mode=True, require_totp=False,
                                engine_config_path=self.engine, honeypot_paths=(self.honeypot,))
        self.fixture.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory(settings=self.settings))
        self.fixture.thread = threading.Thread(target=self.fixture.server.serve_forever, daemon=True)
        self.fixture.thread.start()
        self.request = self.fixture.request
        self.admin = self.headers("admin", "Admin-password-123")
        self.viewer = self.headers("viewer", "Viewer-password-123")
        now = datetime.now(timezone.utc)
        self.fixture.paths["decisions"].write_text(json.dumps({"event_id": "decision-one", "start_time": now.isoformat(),
            "source_ip": "192.0.2.1", "protocol": "ssh", "severity": 1, "signature_id": 2200901,
            "action": "redirect_ssh", "profile": "cowrie"}) + "\n")
        self.honeypot.write_text(json.dumps({"session_id": "session-one", "decision_id": "decision-one",
            "source_ip": "192.0.2.1", "profile": "cowrie", "first_action": (now-timedelta(minutes=2)).isoformat(),
            "last_action": (now-timedelta(minutes=1)).isoformat(), "actions": 3}) + "\n")

    def tearDown(self):
        self.fixture.tearDown()

    def headers(self, username, password):
        status, headers, data = self.fixture.request("POST", "/api/login", {"username": username, "password": password})
        self.assertEqual(status, 200)
        return {"Cookie": headers["Set-Cookie"].split(";")[0], "X-CSRF-Token": data["csrf_token"]}

    def test_notification_state_is_persistent_and_private(self):
        data = self.request("GET", "/api/events.json", headers=self.viewer)[2]
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["dwell_seconds"], 60)
        self.assertEqual(self.request("POST", "/api/events/update", {"id": "decision-one", "action": "read"}, self.viewer)[0], 200)
        self.assertEqual(self.request("GET", "/api/events.json?status=read", headers=self.viewer)[2]["total"], 1)
        self.assertEqual(self.request("GET", "/api/events.json", headers=self.admin)[2]["unread"], 1)
        self.assertEqual(self.request("POST", "/api/events/update", {"id": "decision-one", "action": "deleted"}, self.viewer)[0], 200)
        self.assertEqual(self.request("GET", "/api/events.json", headers=self.viewer)[2]["total"], 0)
        self.assertEqual(json.loads(self.fixture.paths["users"].with_name("dashboard-state.json").read_text())["notifications"]["viewer"]["decision-one"], "deleted")
        self.assertEqual(self.request("POST", "/api/events/update", {"id": "other", "action": "read"}, self.viewer)[0], 400)

    def test_dwell_reports_filters_and_csv(self):
        report = self.request("GET", "/api/analytics.json?window=24h", headers=self.viewer)[2]
        self.assertEqual(report["honeypot_dwell"], [{"profile": "cowrie", "sessions": 1, "average_seconds": 60}])
        self.assertEqual(report["decision_protocols"], {"SSH": 1})
        self.assertIn("cowrie,1,60", report_csv(report))
        result = self.request("GET", "/api/logs.json?type=honeypot", headers=self.viewer)[2]
        self.assertEqual(result["total"], 1)
        self.assertIn("60.0s", result["items"][0]["summary"])
        older = analytics([], [], "24h", now=datetime.now(timezone.utc)+timedelta(days=2), sessions=[{
            "first_action": datetime.now(timezone.utc).isoformat(), "profile": "cowrie", "dwell_seconds": 60}])
        self.assertEqual(older["honeypot_sessions"], 0)

    def test_admin_permissions_threshold_validation_and_rule_backup(self):
        self.assertEqual(self.request("POST", "/api/thresholds", {"monitor": 10, "redirect": 35}, self.viewer)[0], 403)
        self.assertEqual(self.request("POST", "/api/thresholds", {"monitor": 50, "redirect": 30}, self.admin)[0], 400)
        self.assertEqual(self.request("POST", "/api/thresholds", {"monitor": 10, "redirect": 35}, self.admin)[0], 200)
        self.assertEqual(json.loads(self.engine.read_text())["thresholds"]["redirect"], 35)
        rule = 'alert tcp any any -> any any (msg:"added"; classtype:network-scan; sid:9901001; rev:1;)'
        self.assertEqual(self.request("POST", "/api/rules/change", {"action": "add", "rule": rule}, self.viewer)[0], 403)
        status, _, result = self.request("POST", "/api/rules/change", {"action": "add", "rule": rule}, self.admin)
        self.assertEqual(status, 200)
        self.assertEqual(len(read_rules(self.settings.active_rules_path)), 2)
        self.assertEqual(self.request("POST", "/api/rules/change", {"action": "add", "rule": rule}, self.admin)[0], 400)
        self.request("POST", "/api/rules/change", {"action": "toggle", "sid": 9901001, "enabled": False}, self.admin)
        self.assertFalse(read_rules(self.settings.active_rules_path)[1]["enabled"])
        self.assertEqual(self.request("POST", "/api/rules/change", {"action": "restore", "backup": "../users.json"}, self.admin)[0], 400)
        self.request("POST", "/api/rules/change", {"action": "restore", "backup": result["backup"]}, self.admin)
        self.assertEqual(len(read_rules(self.settings.active_rules_path)), 1)

    def test_user_edit_role_delete_and_last_admin(self):
        self.assertEqual(self.request("POST", "/api/users/viewer/edit", {"name": "Analyst", "role": "master_admin"}, self.viewer)[0], 403)
        self.assertEqual(self.request("POST", "/api/users/admin/delete", {}, self.admin)[0], 404)
        self.assertEqual(self.request("POST", "/api/users/viewer/edit", {"name": "Analyst", "role": "master_admin"}, self.admin)[0], 200)
        self.assertEqual(self.request("GET", "/api/events.json", headers=self.viewer)[0], 401)
        self.assertEqual(UserStore(self.settings.users_path).load()["viewer"]["role"], "master_admin")
        self.assertEqual(self.request("POST", "/api/users/viewer/delete", {}, self.admin)[0], 200)
        self.assertNotIn("viewer", UserStore(self.settings.users_path).load())

    def test_flush_requires_totp_preserves_logs_and_accepts_new_events(self):
        self.assertEqual(self.request("POST", "/api/logs/flush", {"confirmation": "FLUSH", "totp": "123456"}, self.viewer)[0], 403)
        store = UserStore(self.settings.users_path)
        secret = store.setup_totp("viewer", "Viewer-password-123")
        counter = int(time.time()) // 30
        with patch("defender.dashboard.security.time.time", return_value=counter*30):
            store.setup_totp("viewer", "Viewer-password-123", totp_code(secret, counter))
        with patch("defender.dashboard.security.time.time", return_value=(counter+1)*30):
            self.assertEqual(self.request("POST", "/api/logs/flush", {"confirmation": "FLUSH", "totp": totp_code(secret, counter+1)}, self.viewer)[0], 200)
        self.assertTrue(self.settings.decisions_path.read_text())
        self.assertEqual(self.request("GET", "/api/analytics.json?window=all", headers=self.viewer)[2]["total_decisions"], 0)
        with self.settings.decisions_path.open("a") as stream:
            stream.write(json.dumps({"start_time": datetime.now(timezone.utc).isoformat(), "action": "monitor"})+'\n')
        self.assertEqual(self.request("GET", "/api/analytics.json?window=all", headers=self.viewer)[2]["total_decisions"], 1)

    def test_cowrie_duration_uses_actions_not_connection(self):
        raw = [{"session": "one", "src_ip": "192.0.2.2", "timestamp": stamp,
                "eventid": event} for stamp, event in [
                    ("2026-10-01T10:00:00Z", "cowrie.session.connect"),
                    ("2026-10-01T10:01:00Z", "cowrie.login.failed"),
                    ("2026-10-01T10:02:00Z", "cowrie.command.input"),
                    ("2026-10-01T10:10:00Z", "cowrie.session.closed")]]
        sessions = sessions_from_events([honeypot_transform(event, Path("cowrie.json")) for event in raw])
        self.assertEqual(sessions[0]["dwell_seconds"], 60)

    def test_candidate_queue_approval_revalidates_and_backs_up(self):
        payload = {"rule_id": "new-probe", "version": "1.0.0", "evidence": "test log", "confidence": .9,
                   "expected_sid": 9901101,
                   "rule": 'alert http any any -> any any (msg:"probe"; classtype:web-application-attack; metadata:severity medium; threshold:type limit, track by_src, count 1, seconds 60; sid:9901101; rev:1;)'}
        self.assertEqual(self.request("POST", "/api/candidates/save", payload, self.viewer)[0], 403)
        self.assertEqual(self.request("POST", "/api/candidates/save", payload, self.admin)[0], 200)
        self.assertEqual(self.request("GET", "/api/candidates.json", headers=self.admin)[2]["items"][0]["status"], "pending")
        status, _, result = self.request("POST", "/api/candidates/approve", {"rule_id": "new-probe"}, self.admin)
        self.assertEqual(status, 200)
        self.assertTrue(result["backup"])
        self.assertEqual(len(read_rules(self.settings.active_rules_path)), 2)
        self.assertEqual(self.request("POST", "/api/candidates/approve", {"rule_id": "new-probe"}, self.admin)[0], 400)

    def test_engine_reloads_thresholds_without_losing_risk_state(self):
        from defender.decision_engine.adaptive_defender.config import load_settings
        from defender.decision_engine.adaptive_defender.engine import DecisionEngine
        root = self.engine.parent
        raw = json.loads((Path(__file__).resolve().parents[1] / "defender/decision_engine/config/lab.json").read_text())
        for field in ("eve_path", "checkpoint_path", "audit_path", "nginx_map_path"):
            raw[field] = str(root / (field + ".json"))
        Path(raw["eve_path"]).write_text("")
        self.engine.write_text(json.dumps(raw))
        engine = DecisionEngine(load_settings(self.engine))
        original_states = engine.risk.states
        self.request("POST", "/api/thresholds", {"monitor": 12, "redirect": 39}, self.admin)
        engine.run_once()
        self.assertEqual(engine.risk.thresholds["redirect"], 39)
        self.assertIs(engine.risk.states, original_states)

    def test_master_default_password_requires_change(self):
        store = UserStore(self.settings.users_path)
        users = store.load()
        users["admin"]["must_change_password"] = True
        store._save(users)
        headers = self.headers("admin", "Admin-password-123")
        self.assertEqual(self.request("GET", "/api/events.json", headers=headers)[0], 403)
        self.assertEqual(self.request("POST", "/api/account/password", {
            "current_password": "Admin-password-123", "new_password": "Changed-password-123"}, headers)[0], 200)
        self.assertFalse(store.load()["admin"]["must_change_password"])


if __name__ == "__main__":
    unittest.main()
