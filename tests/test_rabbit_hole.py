from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
import http.client
from http.server import ThreadingHTTPServer
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
import zipfile

from defender.rabbit_hole import analytics, shell
from defender.rabbit_hole.config import DEFAULTS, load, validate_raw
from defender.rabbit_hole.render import Faker, render
from defender.rabbit_hole.scenario import available, check_limits, check_templates
from defender.rabbit_hole.web import WebEngine


def write_config(directory: Path, **overrides) -> Path:
    raw = json.loads(json.dumps(DEFAULTS))
    raw.update({"project_root": str(directory), "secret_path": "rabbit.secret"})
    raw["web"]["log_path"] = "web.jsonl"
    for key, value in overrides.items():
        if isinstance(value, dict):
            raw[key].update(value)
        else:
            raw[key] = value
    path = directory / "rabbit-hole.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


class Clock:
    def __init__(self):
        self.value = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc).timestamp()

    def __call__(self):
        return self.value


class ScenarioTests(unittest.TestCase):
    def test_shipped_scenarios_fit_document_limits(self):
        catalog = available()
        self.assertEqual({"web-backup-api", "web-env-admin", "linux-server"}, set(catalog))
        for scenario in catalog.values():
            self.assertEqual(check_limits(scenario, {"max_depth": 5, "max_branches": 2}), [], scenario.id)
            self.assertEqual(check_templates(scenario, DEFAULTS["organization"]), [], scenario.id)

    def test_faker_is_stable_per_seed_and_differs_between_sessions(self):
        org = DEFAULTS["organization"]
        first = Faker(b"k" * 32, "web:a", org, date(2026, 1, 1))
        again = Faker(b"k" * 32, "web:a", org, date(2026, 1, 1))
        other = Faker(b"k" * 32, "web:b", org, date(2026, 1, 1))
        template = "{{secret:password:db}} {{secret:token:api}} {{person:1:email}}"
        self.assertEqual(render(template, first, {}), render(template, again, {}))
        self.assertNotEqual(render(template, first, {}), render(template, other, {}))
        with self.assertRaises(KeyError):
            render("{{unknown}}", first, {})

    def test_config_validation_rejects_bad_values(self):
        with self.assertRaises(ValueError):
            validate_raw({"organization": {"domain": "bad domain/../"}})
        with self.assertRaises(ValueError):
            validate_raw({"limits": {"max_depth": 50}})
        with self.assertRaises(ValueError):
            validate_raw({"organization": {"internal_subnet": "8.8.8"}})


class WebEngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = load(write_config(self.root))
        self.clock = Clock()
        self.engine = WebEngine(self.config, clock=self.clock)
        self.paths = {}
        for scenario in self.engine.scenarios:
            self.paths.update(scenario.node_paths())

    def tearDown(self):
        self.tmp.cleanup()

    def get(self, path, cookie=None, headers=None, method="GET", body=b"", peer="192.0.2.10"):
        sent = {"User-Agent": "unit-test", **(headers or {})}
        if cookie:
            sent["Cookie"] = "PHPSESSID=" + cookie
        self.clock.value += 10
        return self.engine.handle(method, path, sent, body, (peer, 40000), ("10.0.0.2", 8084))

    def test_clue_chain_depth_and_consistency(self):
        first = self.get("/robots.txt")
        cookie = first.headers["Set-Cookie"].split("=", 1)[1].split(";")[0]
        self.assertIn(self.paths["backup-index"], first.body.decode())
        listing = self.get(self.paths["backup-index"], cookie)
        self.assertEqual(listing.event["clue_from"], "robots")
        self.assertTrue(listing.event["followed_clue"])
        config_one = self.get(self.paths["backup-config"], cookie).body
        config_two = self.get(self.paths["backup-config"], cookie).body
        self.assertEqual(config_one, config_two)
        other = self.get(self.paths["backup-config"], peer="192.0.2.99").body
        self.assertNotEqual(config_one, other)
        api = self.get(self.paths["api-index"], cookie)
        self.assertEqual(api.event["depth"], 3)
        self.assertEqual(api.event["link"], "cookie")

    def test_api_requires_key_from_config_and_links_sessions(self):
        cookie = self.get("/robots.txt").headers["Set-Cookie"].split("=", 1)[1].split(";")[0]
        key = json.loads(self.get(self.paths["backup-config"], cookie).body)["api"]["key"]
        denied = self.get(self.paths["api-users"], cookie)
        self.assertEqual(denied.status, 401)
        self.assertEqual(denied.event["action"], "call_api_denied")
        allowed = self.get(self.paths["api-users"], cookie, {"X-API-Key": key})
        self.assertEqual(allowed.status, 200)
        detail = self.get(self.paths["api-users"] + "/1003", headers={"X-API-Key": key}, peer="198.51.100.4")
        self.assertEqual(detail.status, 200)
        self.assertEqual(detail.event["link"], "api_key")
        self.assertEqual(detail.event["linked_session"], cookie)
        self.assertEqual(self.get(self.paths["api-users"] + "/5", cookie, {"X-API-Key": key}).status, 404)

    def test_form_post_records_fields_and_redirects_to_next_clue(self):
        response = self.get(self.paths["admin-login"], method="POST",
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            body=b"username=admin&password=secret")
        self.assertEqual(response.status, 302)
        self.assertEqual(response.headers["Location"], self.paths["admin-home"])
        self.assertEqual(response.event["form_fields"], ["password", "username"])
        self.assertEqual(response.event["payload"], "username=admin&password=secret")

    def test_limits_unknown_paths_and_disabled_mode(self):
        self.assertEqual(self.get("/nothing-here").status, 404)
        self.assertEqual(self.get("/backup").status, 301)
        self.assertEqual(self.get("/x", method="DELETE").status, 405)
        limited = WebEngine(load(write_config(self.root, limits={"max_resources_per_session": 2})), clock=self.clock)
        for path, status in [("/robots.txt", 200), ("/.env", 200), (self.paths["backup-index"], 404)]:
            response = limited.handle("GET", path, {"User-Agent": "x"}, b"", ("192.0.2.1", 1), ("10.0.0.2", 80))
            self.assertEqual(response.status, status)
        self.assertTrue(response.event["limit_reached"])
        disabled = WebEngine(load(write_config(self.root, enabled=False)), clock=self.clock)
        self.assertEqual(disabled.handle("GET", "/.env", {}, b"", ("192.0.2.1", 1), ("10.0.0.2", 80)).status, 404)

    def test_proxy_headers_trusted_only_from_configured_proxy(self):
        spoofed = self.get("/robots.txt", headers={"X-Real-IP": "203.0.113.9"}, peer="192.0.2.50")
        self.assertEqual(spoofed.event["source_ip"], "192.0.2.50")
        proxied = self.get("/robots.txt", headers={"X-Real-IP": "203.0.113.9", "X-Real-Port": "5555"},
                           peer="127.0.0.1")
        self.assertEqual((proxied.event["source_ip"], proxied.event["source_port"]), ("203.0.113.9", 5555))

    def test_logged_headers_mask_cookies(self):
        response = self.get("/robots.txt", cookie="a" * 32)
        self.assertNotIn("a" * 32, json.dumps(response.event["headers"]))


class AnalyticsTests(unittest.TestCase):
    @staticmethod
    def event(at, node="robots", session="s1", depth=1, followed=False, status=200):
        return {"event": "rabbit_hole.web", "timestamp": at.isoformat(), "session_id": session,
                "node_id": node, "resource_id": node, "scenario": "web-backup-api", "depth": depth,
                "followed_clue": followed, "status": status, "protocol": "http", "source_ip": "192.0.2.1",
                "action": "read_file", "link": "cookie"}

    def test_document_example_duration_and_idle_split(self):
        start = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)
        events = [self.event(start), self.event(start + timedelta(seconds=150), "backup-index", depth=2, followed=True),
                  self.event(start + timedelta(minutes=20), "env")]
        result = analytics.windows(events, 300, now=start + timedelta(hours=1))
        result.sort(key=lambda w: w["start"])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["duration_seconds"], 150.0)
        self.assertEqual(result[0]["end_reason"], "idle_timeout")
        self.assertTrue(result[0]["followed"])
        self.assertEqual(result[0]["max_depth"], 2)
        self.assertTrue(result[1]["single_access"])
        self.assertIsNone(result[1]["duration_seconds"])
        summary = analytics.summarize(result)
        self.assertEqual(summary["overall"]["sessions"], 1)
        self.assertEqual(summary["overall"]["sessions_followed"], 1)

    def test_window_starts_only_at_successful_decoy_access(self):
        start = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)
        events = [self.event(start, node=None), self.event(start, "api-users", status=401),
                  self.event(start + timedelta(seconds=30))]
        result = analytics.windows(events, 300, now=start)
        self.assertEqual(result[0]["start"], (start + timedelta(seconds=30)).isoformat())


class ShellTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = load(write_config(Path(self.tmp.name)))
        self.paths = self.config.selected("shell")[0].node_paths()

    def tearDown(self):
        self.tmp.cleanup()

    def cowrie(self, *commands, user="sysadmin"):
        base = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)
        events = [{"eventid": "cowrie.session.connect", "session": "c1", "protocol": "telnet",
                   "timestamp": base.isoformat(), "src_ip": "192.0.2.7"},
                  {"eventid": "cowrie.login.success", "session": "c1", "username": user,
                   "timestamp": (base + timedelta(seconds=1)).isoformat(), "src_ip": "192.0.2.7"}]
        for index, command in enumerate(commands):
            events.append({"eventid": "cowrie.command.input", "session": "c1", "input": command,
                           "timestamp": (base + timedelta(seconds=10 * (index + 1))).isoformat(),
                           "src_ip": "192.0.2.7"})
        events.append({"eventid": "cowrie.session.closed", "session": "c1", "duration": 99.0,
                       "timestamp": (base + timedelta(seconds=200)).isoformat(), "src_ip": "192.0.2.7"})
        return shell.events_from_cowrie(events, self.config)

    def test_commands_with_relative_paths_follow_clues(self):
        events = self.cowrie("ls", "cat notes.txt", "cd /opt/backup && cat backup.conf",
                             "sudo ls " + self.paths["dumps-dir"])
        touched = [(e["node_id"], e["followed_clue"]) for e in events if e["node_id"]]
        self.assertEqual(touched, [("notes", False), ("backup-conf", True), ("dumps-dir", True)])
        self.assertEqual(events[0]["protocol"], "telnet")
        self.assertEqual(events[-1]["connection_seconds"], 99.0)
        window = analytics.windows(events, 300)[0]
        self.assertEqual(window["end_reason"], "session_closed")
        self.assertEqual(window["connection_seconds"], 99.0)
        self.assertEqual(window["max_depth"], 2)

    def test_cowrie_bundle_contains_files_and_fsctl_commands(self):
        archive = zipfile.ZipFile(io.BytesIO(shell.export_bundle(self.config)))
        names = set(archive.namelist())
        self.assertIn("honeyfs" + self.paths["backup-conf"], names)
        commands = archive.read("fsctl-commands.txt").decode()
        self.assertIn("mkdir /var/backups/db", commands)
        self.assertIn("touch " + self.paths["notes"], commands)
        self.assertIn(self.paths["dumps-dir"], archive.read("honeyfs" + self.paths["backup-conf"]).decode())


class CustomScenarioTests(unittest.TestCase):
    def setUp(self):
        from defender.rabbit_hole import custom
        self.custom = custom
        self.tmp = tempfile.TemporaryDirectory()
        self.config = load(write_config(Path(self.tmp.name)))

    def tearDown(self):
        self.tmp.cleanup()

    def draft(self):
        definition = self.custom.definition(self.config, "linux-server")
        self.assertTrue(definition.pop("builtin"))
        definition.update(id="custom-abc123", title="My server")
        return definition

    def test_template_copy_saves_and_loads_as_custom(self):
        result = self.custom.save(self.config, self.draft())
        self.assertTrue(result["ok"])
        catalog = self.config.all_scenarios()
        self.assertIn("custom-abc123", catalog)
        self.assertFalse(catalog["custom-abc123"].builtin)
        self.assertTrue(catalog["linux-server"].builtin)
        second = self.draft()
        second["title"] = "Edited"
        self.custom.save(self.config, second)
        self.assertEqual(len(list((self.config.custom_dir / ".backups").glob("*.json"))), 1)
        self.custom.delete(self.config, "custom-abc123")
        self.assertNotIn("custom-abc123", self.config.all_scenarios())

    def test_validation_blocks_bad_drafts_and_warns_on_literal_secrets(self):
        draft = self.draft()
        draft["id"] = "linux-server"
        self.assertTrue(self.custom.check(draft, self.config)["errors"])
        draft = self.draft()
        draft["nodes"].append({"id": "orphan", "kind": "file", "path": "/tmp/x.txt", "body": "x", "next": []})
        errors = self.custom.check(draft, self.config)["errors"]
        self.assertTrue(any("/tmp/x.txt" in e for e in errors))
        draft = self.draft()
        draft["nodes"][0]["path"] = "/bad path<script>"
        self.assertTrue(self.custom.check(draft, self.config)["errors"])
        draft = self.draft()
        draft["nodes"][0]["body"] = "DB_PASS=Winter2026!\n{{secret:password:ok}}"
        report = self.custom.check(draft, self.config)
        self.assertEqual(report["errors"], [])
        self.assertTrue(report["warnings"])
        with self.assertRaises(ValueError):
            self.custom.save(self.config, {**self.draft(), "nodes": []})

    def test_selected_scenario_cannot_be_deleted_and_broken_files_are_skipped(self):
        with self.assertRaises(ValueError):
            self.custom.delete(self.config, "linux-server")
        self.config.custom_dir.mkdir(parents=True)
        (self.config.custom_dir / "broken.json").write_text("{not json")
        errors = []
        self.assertIn("web-backup-api", self.config.all_scenarios(errors))
        self.assertTrue(errors)

    def test_web_engine_reloads_when_a_scenario_file_changes(self):
        engine = WebEngine(self.config)
        draft = self.custom.definition(self.config, "web-env-admin")
        draft.pop("builtin")
        draft.update(id="custom-web001", title="Env copy")
        for node in draft["nodes"]:
            node["path"] = "/v2" + node["path"]
        self.custom.save(self.config, draft)
        stored = json.loads(self.config.path.read_text())
        stored["scenarios"]["web"] = ["custom-web001"]
        self.config.path.write_text(json.dumps(stored))
        response = engine.handle("GET", "/v2/.env", {}, b"", ("192.0.2.1", 1), ("10.0.0.2", 80))
        self.assertEqual(response.status, 200)
        self.assertEqual(response.event["scenario"], "custom-web001")


class DashboardRabbitHoleTests(unittest.TestCase):
    def setUp(self):
        import test_dashboard_security as fixtures
        from defender.dashboard.app import handler_factory
        self.fixture = fixtures.DashboardApiSecurityTests()
        self.fixture.setUp()
        self.fixture.server.shutdown()
        self.fixture.server.server_close()
        self.fixture.thread.join()
        root = self.fixture.paths["users"].parent
        self.config_path = write_config(root)
        self.web_log = root / "web.jsonl"
        engine = WebEngine(load(self.config_path))
        paths = {}
        for scenario in engine.scenarios:
            paths.update(scenario.node_paths())
        with self.web_log.open("w") as stream:
            for path in ["/robots.txt", paths["backup-index"], paths["backup-config"]]:
                response = engine.handle("GET", path, {"User-Agent": "t"}, b"", ("192.0.2.3", 1), ("10.0.0.2", 80))
                stream.write(json.dumps(response.event) + "\n")
        settings = replace(self.fixture.settings, require_totp=False, rabbit_hole_config_path=self.config_path,
                           rabbit_hole_log_paths=(self.web_log,))
        self.fixture.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory(settings=settings))
        self.fixture.thread = threading.Thread(target=self.fixture.server.serve_forever, daemon=True)
        self.fixture.thread.start()
        self.request = self.fixture.request
        self.admin = self.headers("admin", "Admin-password-123")
        self.viewer = self.headers("viewer", "Viewer-password-123")

    def tearDown(self):
        self.fixture.tearDown()

    def headers(self, username, password):
        status, headers, data = self.request("POST", "/api/login", {"username": username, "password": password})
        self.assertEqual(status, 200)
        return {"Cookie": headers["Set-Cookie"].split(";")[0], "X-CSRF-Token": data["csrf_token"]}

    def test_report_permissions_and_settings(self):
        self.assertEqual(self.request("GET", "/api/rabbit-hole.json")[0], 401)
        status, _, report = self.request("GET", "/api/rabbit-hole.json?window=all", headers=self.viewer)
        self.assertEqual(status, 200)
        self.assertEqual(report["summary"]["overall"]["sessions"], 1)
        self.assertEqual(report["windows"][0]["max_depth"], 2)
        detail = self.request("GET", "/api/rabbit-hole/window.json?id=" + report["windows"][0]["id"],
                              headers=self.viewer)[2]
        self.assertEqual([step["node_id"] for step in detail["trail"]], ["robots", "backup-index", "backup-config"])
        self.assertNotIn("secret_path", report["settings"])
        self.assertEqual(self.request("GET", "/api/rabbit-hole/preview.json?scenario=web-backup-api",
                                      headers=self.viewer)[0], 403)
        preview = self.request("GET", "/api/rabbit-hole/preview.json?scenario=web-backup-api", headers=self.admin)[2]
        self.assertTrue(any(item["id"] == "backup-config" for item in preview["resources"]))
        logs = self.request("GET", "/api/logs.json?type=rabbit_hole", headers=self.viewer)[2]
        self.assertEqual(logs["total"], 3)
        self.assertEqual(self.request("POST", "/api/rabbit-hole/settings", {"enabled": False}, self.viewer)[0], 403)
        no_csrf = {"Cookie": self.admin["Cookie"]}
        self.assertEqual(self.request("POST", "/api/rabbit-hole/settings", {"enabled": False}, no_csrf)[0], 403)
        bad = self.request("POST", "/api/rabbit-hole/settings", {"scenarios": {"web": ["linux-server"]}}, self.admin)
        self.assertEqual(bad[0], 400)
        saved = self.request("POST", "/api/rabbit-hole/settings",
                             {"enabled": False, "organization": {"name": "Contoso Ltd."}}, self.admin)
        self.assertEqual(saved[0], 200)
        stored = json.loads(self.config_path.read_text())
        self.assertFalse(stored["enabled"])
        self.assertEqual(stored["organization"]["name"], "Contoso Ltd.")
        self.assertEqual(stored["secret_path"], "rabbit.secret")

    def test_scenario_editor_endpoints(self):
        definition = self.request("GET", "/api/rabbit-hole/scenario.json?id=web-backup-api", headers=self.admin)[2]
        self.assertTrue(definition["builtin"])
        self.assertEqual(self.request("GET", "/api/rabbit-hole/scenario.json?id=web-backup-api",
                                      headers=self.viewer)[0], 403)
        definition.pop("builtin")
        definition.update(id="custom-dash01", title="Copy")
        for node in definition["nodes"]:
            node["path"] = "/copy" + node["path"]
        check = self.request("POST", "/api/rabbit-hole/scenario/check", {"definition": definition}, self.admin)[2]
        self.assertEqual(check["errors"], [])
        preview = self.request("POST", "/api/rabbit-hole/scenario/preview", {"definition": definition}, self.admin)[2]
        self.assertTrue(any(r["path"] == "/copy/robots.txt" for r in preview["resources"]))
        self.assertEqual(self.request("POST", "/api/rabbit-hole/scenario/save", {"definition": definition},
                                      self.viewer)[0], 403)
        self.assertEqual(self.request("POST", "/api/rabbit-hole/scenario/save", {"definition": definition},
                                      self.admin)[0], 200)
        report = self.request("GET", "/api/rabbit-hole.json", headers=self.viewer)[2]
        self.assertIn("custom-dash01", {s["id"] for s in report["scenarios"] if not s["builtin"]})
        self.assertEqual(self.request("POST", "/api/rabbit-hole/scenario/delete", {"id": "custom-dash01"},
                                      self.admin)[0], 200)
        self.assertEqual(self.request("POST", "/api/rabbit-hole/scenario/delete", {"id": "web-backup-api"},
                                      self.admin)[0], 400)

    def test_cowrie_bundle_download_is_admin_only(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.fixture.server.server_port, timeout=3)
        connection.request("GET", "/api/rabbit-hole/cowrie-bundle.zip", headers=self.admin)
        response = connection.getresponse()
        body = response.read()
        connection.close()
        self.assertEqual(response.status, 200)
        self.assertIn("fsctl-commands.txt", zipfile.ZipFile(io.BytesIO(body)).namelist())
        self.assertEqual(self.request("GET", "/api/rabbit-hole/cowrie-bundle.zip", headers=self.viewer)[0], 403)


if __name__ == "__main__":
    unittest.main()
