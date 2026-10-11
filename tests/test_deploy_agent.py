from dataclasses import replace
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from defender.deploy_agent.agent import Agent, check_target, handler_factory, load_config, read_env
from defender.deploy_agent.clone import SiteCloner, decode_package, demo_files, encode_package

TOKEN = "t" * 40


def make_agent(root: Path, runner=None, health=None, dry_run=True):
    (root / "token").write_text(TOKEN)
    (root / "settings.env").write_text("SNARE_BIND_IP=127.0.0.1\nSNARE_PAGE_DIR=demo\n")
    (root / "agent.json").write_text(json.dumps({
        "bind_host": "127.0.0.1", "bind_port": 0, "token_file": "token", "allowed_clients": ["127.0.0.1/32"],
        "compose_dir": ".", "env_file": "settings.env", "data_dir": "data", "health_url": "http://127.0.0.1:1/",
        "dry_run": dry_run}))
    return Agent(load_config(root / "agent.json"), runner=runner, health=health)


def wait(job, seconds=10):
    deadline = time.time() + seconds
    while job.status in {"queued", "running"} and time.time() < deadline:
        time.sleep(0.05)
    return job


def package(url="http://www.example.com/", depth=1):
    return encode_package(url, depth, demo_files(url))


class SiteHandler(BaseHTTPRequestHandler):
    """A small real site for the cloner: links, CSS, an off-site redirect and a 404 page."""
    pages = {
        "/": ("text/html", '<a href="/about.html">About</a><a href="http://HOST/contact.html#x">C</a>'
                           '<link href="/style.css" rel="stylesheet"><a href="http://evil.example/">x</a>'
                           '<a href="/away">away</a><img src="/deep.html">'),
        "/about.html": ("text/html", '<a href="/deeper.html">deeper</a>'),
        "/contact.html": ("text/html", "contact"),
        "/style.css": ("text/css", "body{background:url('/bg.png')}"),
        "/bg.png": ("image/png", "PNG"),
        "/deep.html": ("text/html", "deep"),
        "/deeper.html": ("text/html", "too deep"),
    }
    hits = []

    def do_GET(self):
        SiteHandler.hits.append(self.path)
        if self.path == "/away":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.2:1/secret")
            self.end_headers()
            return
        content_type, body = self.pages.get(self.path, ("text/html", "<h1>Not here</h1>"))
        body = body.replace("HOST", self.headers["Host"]).encode()
        self.send_response(200 if self.path in self.pages else 404)
        self.send_header("Content-Type", content_type)
        self.send_header("Set-Cookie", "sid=real-session")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


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

    def test_cloner_stays_on_site_and_writes_snare_format(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), SiteHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        SiteHandler.hits = []
        try:
            root = f"http://127.0.0.1:{server.server_port}/"
            files, meta = SiteCloner(root, 2).run()
        finally:
            server.shutdown()
        self.assertEqual(set(meta), {"/index.html", "/status_404", "/about.html", "/contact.html", "/style.css",
                                     "/deep.html", "/bg.png", "/deeper.html", "/away"})
        index = files[meta["/index.html"]["hash"]].decode()
        self.assertIn('href="/contact.html', index)  # absolute same-site link made relative
        self.assertNotIn("127.0.0.1:", index)
        self.assertNotIn("/secret", SiteHandler.hits)  # off-site redirect not followed
        self.assertTrue(all("evil" not in h for h in SiteHandler.hits))
        self.assertIn("Not here", files[meta["/status_404"]["hash"]].decode())
        for item in meta.values():
            self.assertFalse(any("Set-Cookie" in h for h in item["headers"]))
        url, depth, checked = decode_package(encode_package(root, 2, files))
        self.assertEqual((url, depth, len(checked)), (root, 2, len(files)))
        _, shallow = SiteCloner(root, 1, fetch=lambda u: (200, [("Content-Type", "text/html")],
                                                           b'<a href="/a.html">a</a>')).run()
        self.assertEqual(set(shallow), {"/index.html", "/status_404", "/a.html"})

    def test_store_creates_version_and_scan_findings(self):
        agent = make_agent(self.root)
        record = agent.store(package())
        version = record["version"]
        self.assertTrue(version.startswith("www.example.com-"))
        self.assertEqual((record["pages"], record["cloned_by"]), (4, "defender"))
        self.assertTrue(any(f["rule"] == "internal_ip" for f in record["findings"]))
        self.assertIn("/login.html", agent.page_list(version))
        self.assertIn("password", agent.page(version, "/login.html")[1].decode())
        self.assertEqual(list((self.root / "data/staging").iterdir()), [])
        with self.assertRaises(ValueError):
            agent.page("../../etc", "/index.html")

    def test_store_rejects_bad_packages(self):
        agent = make_agent(self.root)
        good = package()
        bad_name = json.loads(json.dumps(good))
        bad_name["files"]["../../etc/cron.d/x"] = "eA=="
        missing = json.loads(json.dumps(good))
        missing["files"].pop(next(n for n in missing["files"] if n != "meta.json"))
        for payload in (bad_name, missing, {**good, "depth": 9}, {**good, "files": {}}, {}):
            with self.assertRaises(ValueError):
                agent.store(payload)
        self.assertEqual(agent.versions(), {})

    def test_activate_switches_and_rolls_back_when_unhealthy(self):
        agent = make_agent(self.root)
        version = agent.store(package())["version"]
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
            self.assertEqual(call("POST", "/v1/versions", package(), token=None)[0], 401)
            status, data = call("GET", "/v1/status")
            self.assertEqual((status, data["active"]), (200, "demo"))
            # The Honeypot no longer fetches websites itself.
            self.assertEqual(call("POST", "/v1/clone", {"url": "http://www.example.com/", "depth": 1})[0], 404)
            self.assertEqual(call("POST", "/v1/versions", {"url": "http://x/", "depth": 1, "files": {}})[0], 400)
            status, record = call("POST", "/v1/versions", package())
            self.assertEqual(status, 201)
            self.assertIn(record["version"], [v["version"] for v in call("GET", "/v1/status")[1]["versions"]])
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
                           deploy_agent_token_path=root / "token",
                           deploy_allowed_targets=("www.example.com",), deploy_dry_run=True)
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
        status_data = self.request("GET", "/api/web-deploy/status.json", headers=admin)[2]
        self.assertEqual((status_data["active"], status_data["allowed_targets"]), ("demo", ["www.example.com"]))
        self.assertEqual(self.request("POST", "/api/web-deploy/clone", {"url": "http://evil.example/", "depth": 1},
                                      admin)[0], 400)
        status, _, job = self.request("POST", "/api/web-deploy/clone", {"url": "http://www.example.com/", "depth": 1}, admin)
        self.assertEqual(status, 202)
        for _ in range(100):
            job = self.request("GET", "/api/web-deploy/job.json?id=" + job["id"], headers=admin)[2]
            if job["status"] not in {"queued", "running"}:
                break
            time.sleep(0.05)
        self.assertEqual(job["status"], "succeeded", job)
        self.assertTrue(job["id"].startswith("c"))  # cloned on the Defender, not by the agent
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
