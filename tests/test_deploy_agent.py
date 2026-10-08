from dataclasses import replace
import http.client
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from defender.deploy_agent.agent import Agent, check_target, handler_factory, load_config, read_env

TOKEN = "t" * 40


def make_agent(root: Path, runner=None, health=None, dry_run=True):
    (root / "token").write_text(TOKEN)
    (root / "settings.env").write_text("SNARE_BIND_IP=127.0.0.1\nSNARE_PAGE_DIR=demo\n")
    (root / "agent.json").write_text(json.dumps({
        "bind_host": "127.0.0.1", "bind_port": 0, "token_file": "token", "allowed_clients": ["127.0.0.1/32"],
        "allowed_targets": ["10.10.10.3:8080", "www.example.com"], "compose_dir": ".",
        "env_file": "settings.env", "data_dir": "data", "health_url": "http://127.0.0.1:1/", "dry_run": dry_run}))
    return Agent(load_config(root / "agent.json"), runner=runner, health=health)


def wait(job, seconds=10):
    deadline = time.time() + seconds
    while job.status in {"queued", "running"} and time.time() < deadline:
        time.sleep(0.05)
    return job


class DeployAgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_target_allowlist_blocks_ssrf(self):
        self.assertEqual(check_target("http://10.10.10.3:8080/shop", ["10.10.10.3:8080"]), "http://10.10.10.3:8080/shop")
        for bad in ["http://127.0.0.1/", "file:///etc/passwd", "http://user:pw@www.example.com/",
                    "http://10.10.10.3:9999/", "gopher://www.example.com/", "http://169.254.169.254/"]:
            with self.assertRaises(ValueError, msg=bad):
                check_target(bad, ["10.10.10.3:8080", "www.example.com"])

    def test_clone_creates_version_and_scan_findings(self):
        agent = make_agent(self.root)
        job = wait(agent.clone("http://www.example.com/", 2))
        self.assertEqual(job.status, "succeeded", job.log)
        version = job.result["version"]
        self.assertTrue(version.startswith("www.example.com-"))
        self.assertEqual(job.result["pages"], 4)
        self.assertTrue(any(f["rule"] == "internal_ip" for f in job.result["findings"]))
        self.assertIn("/login.html", agent.page_list(version))
        self.assertIn("password", agent.page(version, "/login.html")[1].decode())
        self.assertFalse((self.root / "data/staging" / job.id).exists())
        with self.assertRaises(ValueError):
            agent.page("../../etc", "/index.html")
        with self.assertRaises(ValueError):
            agent.clone("http://www.example.com/", 9)

    def test_clone_command_is_fixed_argv(self):
        calls = []

        def runner(argv, timeout, log, staging=None, url=""):
            calls.append(argv)
            return 1

        agent = make_agent(self.root, runner=runner, dry_run=False)
        job = wait(agent.clone("http://10.10.10.3:8080/", 1))
        self.assertEqual(job.status, "failed")
        argv = calls[0]
        self.assertEqual(argv[:2], ["docker", "compose"])
        self.assertIn("--rm", argv)
        self.assertEqual(argv[argv.index("--target") + 1], "http://10.10.10.3:8080/")

    def test_activate_switches_and_rolls_back_when_unhealthy(self):
        agent = make_agent(self.root)
        version = wait(agent.clone("http://www.example.com/", 1)).result["version"]
        job = wait(agent.activate(version))
        self.assertEqual(job.status, "succeeded")
        self.assertEqual(read_env(self.root / "settings.env")["SNARE_PAGE_DIR"], version)
        self.assertTrue(agent.status()["versions"][0]["active"])
        broken = Agent(agent.config, health=lambda: False)
        broken._wait_healthy = lambda job, seconds=60: False
        job = wait(broken.activate("demo"))
        self.assertEqual(job.status, "failed")
        self.assertIn("rolled_back", job.error)
        self.assertEqual(read_env(self.root / "settings.env")["SNARE_PAGE_DIR"], version)
        with self.assertRaises(ValueError):
            agent.activate("../evil")

    def test_http_api_requires_token(self):
        agent = make_agent(self.root)
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory(agent))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            def call(method, path, body=None, token=TOKEN):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                headers = {"Content-Type": "application/json"}
                if token:
                    headers["Authorization"] = "Bearer " + token
                connection.request(method, path, body=json.dumps(body) if body else None, headers=headers)
                response = connection.getresponse()
                return response.status, json.loads(response.read() or b"{}")
            self.assertEqual(call("GET", "/v1/status", token=None)[0], 401)
            self.assertEqual(call("GET", "/v1/status", token="x" * 40)[0], 401)
            status, data = call("GET", "/v1/status")
            self.assertEqual((status, data["active"]), (200, "demo"))
            self.assertEqual(call("POST", "/v1/clone", {"url": "http://evil.example/", "depth": 1})[0], 400)
            status, job = call("POST", "/v1/clone", {"url": "http://www.example.com/", "depth": 1})
            self.assertEqual(status, 202)
            self.assertEqual(call("POST", "/v1/clone", {"url": "http://www.example.com/", "depth": 1})[0], 409)
        finally:
            server.shutdown()


class DashboardDeployTests(unittest.TestCase):
    def setUp(self):
        import test_dashboard_security as fixtures
        from defender.dashboard.app import handler_factory as dashboard_handler
        from defender.dashboard.security import UserStore
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.agent = make_agent(root)
        self.agent_server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory(self.agent))
        threading.Thread(target=self.agent_server.serve_forever, daemon=True).start()
        self.fixture = fixtures.DashboardApiSecurityTests()
        self.fixture.setUp()
        self.fixture.server.shutdown()
        self.fixture.server.server_close()
        self.fixture.thread.join()
        settings = replace(self.fixture.settings, require_totp=False,
                           deploy_agent_url=f"http://127.0.0.1:{self.agent_server.server_port}",
                           deploy_agent_token_path=root / "token")
        self.fixture.server = ThreadingHTTPServer(("127.0.0.1", 0), dashboard_handler(settings=settings))
        self.fixture.thread = threading.Thread(target=self.fixture.server.serve_forever, daemon=True)
        self.fixture.thread.start()
        self.request = self.fixture.request
        self.store = UserStore(self.fixture.paths["users"])

    def tearDown(self):
        self.fixture.tearDown()
        self.agent_server.shutdown()
        self.tmp.cleanup()

    def headers(self, username, password):
        status, headers, data = self.request("POST", "/api/login", {"username": username, "password": password})
        self.assertEqual(status, 200)
        return {"Cookie": headers["Set-Cookie"].split(";")[0], "X-CSRF-Token": data["csrf_token"]}

    def test_clone_and_deploy_through_dashboard(self):
        admin = self.headers("admin", "Admin-password-123")
        viewer = self.headers("viewer", "Viewer-password-123")
        self.assertEqual(self.request("GET", "/api/web-deploy/status.json", headers=viewer)[0], 403)
        self.assertEqual(self.request("GET", "/api/web-deploy/status.json", headers=admin)[2]["active"], "demo")
        self.assertEqual(self.request("POST", "/api/web-deploy/clone", {"url": "http://evil.example/", "depth": 1},
                                      admin)[0], 400)
        status, _, job = self.request("POST", "/api/web-deploy/clone", {"url": "http://www.example.com/", "depth": 1}, admin)
        self.assertEqual(status, 202)
        for _ in range(100):
            job = self.request("GET", "/api/web-deploy/job.json?id=" + job["id"], headers=admin)[2]
            if job["status"] not in {"queued", "running"}:
                break
            time.sleep(0.05)
        version = job["result"]["version"]
        page = self.request("GET", f"/api/web-deploy/page.json?version={version}&url=/index.html", headers=admin)[2]
        self.assertIn("www.example.com", page["content"])
        bad = {"version": version, "confirmation": "DEPLOY", "password": "wrong"}
        self.assertEqual(self.request("POST", "/api/web-deploy/activate", bad, admin)[0], 403)
        good = {"version": version, "confirmation": "DEPLOY", "password": "Admin-password-123"}
        self.assertEqual(self.request("POST", "/api/web-deploy/activate", good, admin)[0], 202)
        self.assertIn("web_deploy_activate", self.fixture.paths["audit"].read_text())


if __name__ == "__main__":
    unittest.main()
