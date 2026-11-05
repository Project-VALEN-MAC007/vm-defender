import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error

from defender.rabbit_hole import analytics, jev
from defender.rabbit_hole.config import DEFAULTS, load, validate_raw
from defender.dashboard.rabbit import RabbitHoleService

KEY = "apikey_test_0123456789abcdef"


def web_event(second, path, node=None, depth=None, followed=False, status=200, sid="a" * 32):
    return {"timestamp": f"2026-10-01T10:00:{second:02d}+00:00", "event": "rabbit_hole.web",
            "session_id": sid, "source_ip": "192.168.56.1", "method": "GET", "path": path,
            "status": status, "node_id": node, "resource_id": node, "depth": depth,
            "scenario": "web-backup-api" if node else None, "action": "read_file" if node else "request",
            "followed_clue": followed, "user_agent": "curl/8.4", "link": "cookie"}


EVENTS = [web_event(1, "/robots.txt", "robots", 1), web_event(5, "/backup/", "backup", 2, True),
          web_event(9, "/backup/config.json", "config", 3, True), web_event(12, "/wp-login.php", status=404)]

ANSWER = {"model": "jev-1.13.0", "usage": {"input_tokens": 420, "output_tokens": 12},
          "answers": {
              "intent": {"type": "choice", "choice": "credential_hunting", "confidence": 0.82,
                         "probabilities": {"credential_hunting": 0.82, "recon": 0.12, "other": 0.06}},
              "automated": {"type": "noul", "noul": 0.21},
              "skill": {"type": "score", "score": 1.4, "confidence": 0.4},
              "engaged": {"type": "noul", "noul": 0.9}}}


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    def __init__(self, payload=ANSWER, error=None):
        self.payload, self.error, self.requests = payload, error, []

    def __call__(self, request, timeout=None):
        self.requests.append((request, timeout))
        if self.error:
            raise self.error
        return FakeResponse(json.dumps(self.payload).encode())


def window():
    return analytics.windows(EVENTS, 300)[0]


def profiler(opener, **settings):
    cfg = {**DEFAULTS["ai"], "enabled": True, **settings}
    return jev.Profiler(cfg, jev.JevClient(cfg, opener=opener, env={"TYPESAFE_API_KEY": KEY}))


class JevProfilerTests(unittest.TestCase):
    def test_request_matches_systemone_api(self):
        opener = FakeOpener()
        result = profiler(opener).profile(window(), EVENTS)
        request, timeout = opener.requests[0]
        self.assertEqual(request.full_url, "https://api.typesafe.ai/v1/systemone")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + KEY)
        body = json.loads(request.data)
        self.assertEqual(body["model"], "jev-latest")
        self.assertEqual(set(body["questions"]), {"intent", "automated", "skill", "engaged"})
        self.assertEqual({q["type"] for q in body["questions"].values()}, {"choice", "noul", "score"})
        self.assertEqual(timeout, 5)
        self.assertEqual(result["intent"]["label"], "credential_hunting")
        self.assertEqual(result["skill"]["level"], 1)
        self.assertFalse(result["uncertain"])
        self.assertFalse(result["cached"])

    def test_state_has_no_source_ip_and_includes_non_bait_requests(self):
        opener = FakeOpener()
        profiler(opener).profile(window(), EVENTS)
        state = json.loads(json.loads(opener.requests[0][0].data)["state"])
        self.assertNotIn("192.168.56.1", json.dumps(state))
        self.assertEqual([s["target"] for s in state["steps"]],
                         ["/robots.txt", "/backup/", "/backup/config.json", "/wp-login.php"])
        self.assertIn("untrusted", state["note"])

    def test_state_is_bounded(self):
        many = [web_event(i % 60, "/x" * 300, status=404) for i in range(500)]
        for i, event in enumerate(many):
            event["timestamp"] = f"2026-10-01T10:{i // 60:02d}:{i % 60:02d}+00:00"
        item = analytics.windows(many, 300)[0]
        state = jev.build_state(item, many)
        self.assertLessEqual(len(state.encode()), jev.MAX_STATE_BYTES)
        self.assertLessEqual(len(json.loads(state)["steps"]), jev.MAX_STEPS)

    def test_result_is_cached_per_window_state(self):
        opener = FakeOpener()
        p = profiler(opener)
        p.profile(window(), EVENTS)
        again = p.profile(window(), EVENTS)
        self.assertTrue(again["cached"])
        self.assertEqual(len(opener.requests), 1)

    def test_disabled_and_missing_key_make_no_request(self):
        opener = FakeOpener()
        cfg = dict(DEFAULTS["ai"])
        off = jev.Profiler(cfg, jev.JevClient(cfg, opener=opener, env={"TYPESAFE_API_KEY": KEY}))
        self.assertEqual(off.profile(window())["reason"], "ai_disabled")
        cfg = {**cfg, "enabled": True}
        nokey = jev.Profiler(cfg, jev.JevClient(cfg, opener=opener, env={}))
        self.assertEqual(nokey.profile(window())["reason"], "missing_api_key")
        self.assertEqual(opener.requests, [])

    def test_api_errors_are_reported_without_the_key(self):
        cases = [(urllib.error.HTTPError("u", 401, "no", {}, io.BytesIO(b"")), "jev_http_401"),
                 (urllib.error.URLError("down"), "jev_unreachable"), (TimeoutError(), "jev_unreachable")]
        for error, code in cases:
            result = profiler(FakeOpener(error=error)).profile(window(), EVENTS)
            self.assertEqual(result["error"], code)
            self.assertNotIn(KEY, json.dumps(result))
        bad = profiler(FakeOpener(payload={"oops": 1})).profile(window(), EVENTS)
        self.assertEqual(bad["error"], "jev_bad_response")

    def test_unexpected_labels_and_low_confidence(self):
        payload = {"model": "jev", "answers": {"intent": {"choice": "<script>", "confidence": 0.2,
                                                          "probabilities": {"<script>": 1}}}}
        result = profiler(FakeOpener(payload=payload)).profile(window(), EVENTS)
        self.assertEqual(result["intent"]["label"], "other")
        self.assertEqual(result["intent"]["probabilities"], {})
        self.assertTrue(result["uncertain"])
        self.assertIsNone(result["skill"]["level"])


class JevConfigTests(unittest.TestCase):
    def test_defaults_are_off(self):
        self.assertFalse(validate_raw({})["ai"]["enabled"])

    def test_rejects_unsafe_settings(self):
        bad = [{"api_url": "http://api.typesafe.ai/v1/systemone"}, {"api_url": "ftp://x"},
               {"provider": "other"}, {"api_key_env": "bad-name"}, {"timeout_seconds": 0},
               {"min_confidence": 2}, {"enabled": "yes"}, {"model": "a b"}]
        for override in bad:
            with self.assertRaises(ValueError, msg=override):
                validate_raw({"ai": override})
        self.assertTrue(validate_raw({"ai": {"api_url": "http://127.0.0.1:9000/v1/systemone"}}))

    def test_dashboard_save_cannot_change_ai_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rabbit-hole.json"
            path.write_text(json.dumps({"project_root": tmp, "secret_path": "s"}), encoding="utf-8")
            config = load(path)
            saved = config.save({"ai": {"enabled": True, "api_url": "https://evil.example/x"}})
            self.assertFalse(saved.ai["enabled"])
            self.assertEqual(saved.ai["api_url"], DEFAULTS["ai"]["api_url"])

    def test_dashboard_service_profiles_a_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rabbit-hole.json"
            path.write_text(json.dumps({"project_root": tmp, "secret_path": "s",
                                        "ai": {"enabled": True}}), encoding="utf-8")
            service = RabbitHoleService(path, Path(tmp))
            opener = FakeOpener()
            p = service.profiler()
            p.client = jev.JevClient(service.config().ai, opener=opener, env={"TYPESAFE_API_KEY": KEY})
            result = service.ai_profile(EVENTS, window()["id"])
            self.assertEqual(result["intent"]["label_th"], "หารหัสผ่าน/คีย์")
            with self.assertRaises(ValueError):
                service.ai_profile(EVENTS, "missing")


class JevDashboardKeyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.path = self.dir / "rabbit-hole.json"
        self.path.write_text(json.dumps({"project_root": self.tmp.name, "secret_path": "s",
                                         "ai": {"api_key_env": "TRAP_TEST_NO_SUCH_VAR"}}), encoding="utf-8")
        self.service = RabbitHoleService(self.path, self.dir)

    def tearDown(self):
        self.tmp.cleanup()

    def test_save_key_and_enable_from_dashboard(self):
        result = self.service.save_ai({"enabled": True, "api_key": KEY})
        self.assertEqual(result["ai"], {"enabled": True, "key_set": True, "key_source": "file",
                                        "key_hint": "…" + KEY[-4:], "key_env": "TRAP_TEST_NO_SUCH_VAR"})
        key_file = self.dir / "config" / "jev.key"
        self.assertEqual(key_file.read_text(encoding="utf-8").strip(), KEY)
        self.assertNotIn(KEY, self.path.read_text(encoding="utf-8"))
        self.assertNotIn(KEY, json.dumps(result))
        self.assertTrue(json.loads(self.path.read_text(encoding="utf-8"))["ai"]["enabled"])
        self.assertNotIn("api_key_path", self.service.config().public()["ai"])
        opener = FakeOpener()
        self.service.profiler().client.opener = opener
        self.service.ai_profile(EVENTS, window()["id"])
        self.assertEqual(opener.requests[0][0].get_header("Authorization"), "Bearer " + KEY)

    def test_blank_key_keeps_existing_and_clear_removes(self):
        self.service.save_ai({"api_key": KEY})
        self.service.save_ai({"enabled": True, "api_key": ""})
        self.assertTrue(self.service.ai_status()["key_set"])
        self.service.save_ai({"clear_key": True})
        self.assertFalse(self.service.ai_status()["key_set"])
        self.assertTrue(self.service.ai_status()["enabled"])

    def test_rejects_bad_key_and_bad_enabled(self):
        for payload in ({"api_key": "short"}, {"api_key": "has space in it 1234567"}, {"api_key": 123},
                        {"enabled": "yes"}):
            with self.assertRaises(ValueError, msg=payload):
                self.service.save_ai(payload)
        self.assertFalse((self.dir / "config" / "jev.key").exists())

    def test_connection_test(self):
        self.assertEqual(self.service.test_ai(), {"ok": False, "error": "missing_api_key"})
        self.service.save_ai({"api_key": KEY})
        self.service.profiler().client.opener = FakeOpener(payload={"model": "jev-1.13.0", "answers": {}})
        self.assertEqual(self.service.test_ai(), {"ok": True, "model": "jev-1.13.0"})


if __name__ == "__main__":
    unittest.main()
