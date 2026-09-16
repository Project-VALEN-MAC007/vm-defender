import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest

from defender.dashboard.app import handler_factory
from defender.dashboard.config import DashboardSettings
from defender.dashboard.security import hash_password
from http.server import ThreadingHTTPServer


class DashboardApiSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.paths = {
            "decisions": root / "decisions.jsonl",
            "status": root / "status.json",
            "eve": root / "eve.json",
            "users": root / "users.json",
            "audit": root / "security.jsonl",
            "rules": root / "local.rules",
            "baseline": root / "baseline.json",
            "registry": root / "registry.jsonl",
            "backups": root / "backups",
        }
        self.paths["decisions"].write_text("", encoding="utf-8")
        self.paths["eve"].write_text("", encoding="utf-8")
        self.paths["status"].write_text('{"suricata":"active"}', encoding="utf-8")
        self.paths["rules"].write_text(
            'alert tcp any any -> any any (msg:"test"; classtype:network-scan; '
            'metadata:severity low; threshold:type limit, track by_src, count 1, '
            'seconds 60; sid:2200901; rev:1;)\n', encoding="utf-8")
        self.paths["baseline"].write_text(json.dumps([
            {"expected_malicious": False, "candidate_alert": False},
            {"expected_malicious": True, "candidate_alert": True},
        ]), encoding="utf-8")
        self.paths["users"].write_text(json.dumps({"users": [
            {"username": "admin", "name": "Admin", "role": "master_admin",
             "password_hash": hash_password("Admin-password-123")},
            {"username": "viewer", "name": "Viewer", "role": "user",
             "password_hash": hash_password("Viewer-password-123")},
        ]}), encoding="utf-8")
        settings = DashboardSettings(
            decisions_path=self.paths["decisions"], status_path=self.paths["status"],
            eve_paths=(self.paths["eve"],), users_path=self.paths["users"],
            security_audit_path=self.paths["audit"], active_rules_path=self.paths["rules"],
            baseline_path=self.paths["baseline"], rule_registry_path=self.paths["registry"],
            rule_backup_dir=self.paths["backups"], suricata_config_path=root / "suricata.yaml",
            login_max_attempts=2,
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory(settings=settings))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, payload=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        body = None if payload is None else json.dumps(payload)
        request_headers = dict(headers or {})
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        raw = response.read()
        result = (response.status, dict(response.getheaders()),
                  json.loads(raw) if raw else None)
        connection.close()
        return result

    def login(self, username, password):
        status, headers, payload = self.request(
            "POST", "/api/login", {"username": username, "password": password})
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        return cookie, payload["csrf_token"]

    def test_api_requires_authentication(self):
        status, _, payload = self.request("GET", "/api/alerts.json")
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "authentication_required")

    def test_user_cannot_access_rule_management(self):
        cookie, _ = self.login("viewer", "Viewer-password-123")
        status, _, payload = self.request("GET", "/api/rules.json", headers={"Cookie": cookie})
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "forbidden")

    def test_admin_can_access_rules_and_receives_security_headers(self):
        cookie, _ = self.login("admin", "Admin-password-123")
        status, headers, payload = self.request("GET", "/api/rules.json", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertEqual(payload[0]["sid"], 2200901)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("HttpOnly", self.request("POST", "/api/login", {
            "username": "admin", "password": "Admin-password-123"})[1]["Set-Cookie"])

    def test_csrf_is_required_for_logout(self):
        cookie, csrf = self.login("admin", "Admin-password-123")
        status, _, _ = self.request("POST", "/api/logout", headers={"Cookie": cookie})
        self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/api/logout", headers={
            "Cookie": cookie, "X-CSRF-Token": csrf})
        self.assertEqual(status, 204)

    def test_login_is_rate_limited(self):
        for expected in (401, 401, 429):
            status, _, _ = self.request("POST", "/api/login", {
                "username": "unknown", "password": "wrong"})
            self.assertEqual(status, expected)

    def test_paginated_response_shape(self):
        cookie, _ = self.login("viewer", "Viewer-password-123")
        status, _, payload = self.request(
            "GET", "/api/alerts.json?limit=25&offset=0", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertEqual(payload["limit"], 25)
        self.assertEqual(payload["items"], [])

    def test_admin_rule_validation_and_deploy_guard(self):
        cookie, csrf = self.login("admin", "Admin-password-123")
        candidate = {
            "rule_id": "dashboard-test-001",
            "version": "1.0.0",
            "evidence": "unit-test-redacted",
            "confidence": 0.9,
            "expected_sid": 2200902,
            "rule": ('alert tcp any any -> any any (msg:"candidate"; '
                     'classtype:network-scan; metadata:severity low; '
                     'threshold:type limit, track by_src, count 1, seconds 60; '
                     'sid:2200902; rev:1;)'),
        }
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, payload = self.request("POST", "/api/rules/validate", candidate, headers)
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["gates"]), 5)
        status, _, payload = self.request("POST", "/api/rules/deploy", candidate, headers)
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"], "rule_deploy_disabled")


if __name__ == "__main__":
    unittest.main()
