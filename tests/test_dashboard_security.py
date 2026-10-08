import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
import base64
import time
from unittest.mock import patch

from defender.dashboard.app import handler_factory
from defender.dashboard.config import DashboardSettings
from defender.dashboard.security import hash_password, totp_code, match_totp, UserStore
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
        self.settings = settings
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
        self.assertTrue(payload["totp_required"])
        self.assertNotIn("Set-Cookie", headers)
        secret = payload.get("enrollment_secret") or UserStore(self.paths["users"]).load()[username]["totp_secret"]
        counter = max(int(time.time()) // 30, UserStore(self.paths["users"]).load()[username]["totp_last_counter"] + 1)
        with patch("defender.dashboard.security.time.time", return_value=counter * 30):
            status, headers, payload = self.request("POST", "/api/login/totp", {
                "challenge": payload["challenge"], "totp": totp_code(secret, counter)})
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        return cookie, payload["csrf_token"]

    def test_api_requires_authentication(self):
        status, _, payload = self.request("GET", "/api/alerts.json")
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "authentication_required")

    def test_totp_rfc_vector_and_expiry(self):
        secret = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(totp_code(secret, 59 // 30, 8), "94287082")
        with patch("defender.dashboard.security.time.time", return_value=59):
            self.assertEqual(match_totp(secret, "287082"), 1)
            self.assertIsNone(match_totp(secret, "287082", 1))
            self.assertIsNone(match_totp(secret, "28708"))
        with patch("defender.dashboard.security.time.time", return_value=150):
            self.assertIsNone(match_totp(secret, "287082"))

    def test_totp_enrollment_login_and_replay(self):
        credentials = {"username": "admin", "password": "Admin-password-123"}
        status, first_headers, challenge = self.request("POST", "/api/login", credentials)
        self.assertEqual(status, 200)
        self.assertTrue(challenge["totp_required"])
        self.assertNotIn("Set-Cookie", first_headers)
        self.assertNotIn("user", challenge)
        secret = challenge["enrollment_secret"]
        self.assertNotIn(secret, self.paths["users"].read_text())
        self.assertEqual(self.request("GET", "/api/alerts.json")[0], 401)
        counter = int(time.time()) // 30
        with patch("defender.dashboard.security.time.time", return_value=counter * 30):
            second = {"challenge": challenge["challenge"], "totp": "bad"}
            self.assertEqual(self.request("POST", "/api/login/totp", second)[0], 401)
            second["totp"] = totp_code(secret, counter)
            status, headers, result = self.request("POST", "/api/login/totp", second)
            self.assertEqual(status, 200)
            self.assertTrue(result["user"]["totp_enabled"])
            self.assertIn("Set-Cookie", headers)
            self.assertEqual(self.request("POST", "/api/login/totp", second)[0], 401)
            _, headers, next_challenge = self.request("POST", "/api/login", credentials)
            self.assertNotIn("enrollment_secret", next_challenge)
            self.assertNotIn("Set-Cookie", headers)
        store = UserStore(self.paths["users"])
        self.assertNotIn(secret, json.dumps(store.list_public()))
        store.change_password("admin", "Admin-password-123", "Changed-password-123")
        self.assertEqual(store.load()["admin"]["totp_secret"], secret)
        self.assertNotIn(secret, self.paths["audit"].read_text())

    def test_totp_challenge_expiry_password_change_and_attempt_limit(self):
        store = UserStore(self.paths["users"])
        secret = store.setup_totp("admin", "Admin-password-123")
        counter = int(time.time()) // 30
        store.setup_totp("admin", "Admin-password-123", totp_code(secret, counter))
        with patch("defender.dashboard.security.time.monotonic", return_value=100):
            challenge = store.begin_login("admin", "Admin-password-123")["challenge"]
        with patch("defender.dashboard.security.time.monotonic", return_value=401):
            self.assertIsNone(store.complete_login(challenge, totp_code(secret, counter + 1)))
        challenge = store.begin_login("admin", "Admin-password-123")["challenge"]
        for _ in range(5):
            self.assertIsNone(store.complete_login(challenge, "bad"))
        self.assertIsNone(store.complete_login(challenge, totp_code(secret, counter + 1)))
        challenge = store.begin_login("admin", "Admin-password-123")["challenge"]
        store.change_password("admin", "Admin-password-123", "Changed-password-123")
        self.assertIsNone(store.complete_login(challenge, totp_code(secret, counter + 1)))
        self.assertIsNone(store.begin_login("admin", "Admin-password-123"))

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
        self.assertIn("trap_session=", cookie)

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

    def test_admin_creates_user_and_password_is_shown_once(self):
        cookie, csrf = self.login("admin", "Admin-password-123")
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, payload = self.request("POST", "/api/users", {
            "username": "analyst01", "name": "Security Analyst"}, headers)
        self.assertEqual(status, 201)
        password = payload["temporary_password"]
        self.assertGreaterEqual(len(password), 12)
        self.assertEqual(payload["user"]["role"], "user")
        new_cookie, _ = self.login("analyst01", password)
        self.assertTrue(new_cookie)
        status, _, listed = self.request("GET", "/api/users.json", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertNotIn("password_hash", json.dumps(listed))
        self.assertNotIn(password, json.dumps(listed))
        status, _, _ = self.request("POST", "/api/users", {
            "username": "analyst01", "name": "Again"}, headers)
        self.assertEqual(status, 409)

    def test_user_cannot_manage_users_or_create_admin(self):
        cookie, csrf = self.login("viewer", "Viewer-password-123")
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        self.assertEqual(self.request("GET", "/api/users.json", headers=headers)[0], 403)
        self.assertEqual(self.request("POST", "/api/users", {
            "username": "another", "name": "Another", "role": "master_admin"}, headers)[0], 403)
        admin_cookie, admin_csrf = self.login("admin", "Admin-password-123")
        status, _, payload = self.request("POST", "/api/users", {
            "username": "another", "name": "Another", "role": "master_admin"},
            {"Cookie": admin_cookie, "X-CSRF-Token": admin_csrf})
        self.assertEqual(status, 201)
        self.assertEqual(payload["user"]["role"], "user")

    def test_disable_reset_and_change_password_revoke_sessions(self):
        admin_cookie, csrf = self.login("admin", "Admin-password-123")
        headers = {"Cookie": admin_cookie, "X-CSRF-Token": csrf}
        viewer_cookie, viewer_csrf = self.login("viewer", "Viewer-password-123")
        status, _, payload = self.request("POST", "/api/users/viewer/status", {"disabled": True}, headers)
        self.assertEqual(status, 200)
        self.assertTrue(payload["user"]["disabled"])
        self.assertEqual(self.request("GET", "/api/alerts.json", headers={"Cookie": viewer_cookie})[0], 401)
        self.assertEqual(self.request("POST", "/api/login", {
            "username": "viewer", "password": "Viewer-password-123"})[0], 401)
        self.assertEqual(self.request("POST", "/api/users/viewer/status", {"disabled": False}, headers)[0], 200)
        viewer_cookie, viewer_csrf = self.login("viewer", "Viewer-password-123")
        status, _, payload = self.request("POST", "/api/users/viewer/reset-password", {}, headers)
        self.assertEqual(status, 200)
        self.assertEqual(self.request("GET", "/api/alerts.json", headers={"Cookie": viewer_cookie})[0], 401)
        viewer_cookie, viewer_csrf = self.login("viewer", payload["temporary_password"])
        status, _, _ = self.request("POST", "/api/account/password", {
            "current_password": payload["temporary_password"], "new_password": "New-viewer-password-123"},
            {"Cookie": viewer_cookie, "X-CSRF-Token": viewer_csrf})
        self.assertEqual(status, 200)
        self.assertEqual(self.request("GET", "/api/alerts.json", headers={"Cookie": viewer_cookie})[0], 401)
        self.login("viewer", "New-viewer-password-123")

    def test_user_creation_needs_csrf_and_valid_name(self):
        cookie, csrf = self.login("admin", "Admin-password-123")
        self.assertEqual(self.request("POST", "/api/users", {
            "username": "tester", "name": "Test"}, {"Cookie": cookie})[0], 403)
        self.assertEqual(self.request("POST", "/api/users", {
            "username": "../bad", "name": "Test"},
            {"Cookie": cookie, "X-CSRF-Token": csrf})[0], 400)

    def test_admin_can_choose_initial_user_password(self):
        cookie, csrf = self.login("admin", "Admin-password-123")
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, payload = self.request("POST", "/api/users", {
            "username": "analyst02", "name": "Analyst Two", "password": "Initial-password-123"}, headers)
        self.assertEqual(status, 201)
        self.assertNotIn("temporary_password", payload)
        self.login("analyst02", "Initial-password-123")
        status, _, payload = self.request("POST", "/api/users", {
            "username": "analyst03", "name": "Analyst Three", "password": "short"}, headers)
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "invalid_password")


if __name__ == "__main__":
    unittest.main()
