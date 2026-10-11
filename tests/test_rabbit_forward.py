"""Rabbit Hole forwards non-bait requests to the decoy web app; bait paths and
logging stay with Rabbit Hole."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest

from defender.rabbit_hole.config import load
from defender.rabbit_hole.web import WebEngine


class FakeUpstream(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _go(self):
        if self.path == "/":
            body = b"<html><body>Acme Logistics home</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "alsid=abc; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD": self.wfile.write(body)
        else:
            body = b"<html><body>not found</body></html>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD": self.wfile.write(body)
    do_GET = _go
    do_HEAD = _go


def write_config(root: Path, upstream: str) -> Path:
    config = {
        "project_root": "..", "enabled": True,
        "organization": {"name": "Acme Logistics", "short_name": "acme",
                         "domain": "acme-logistics.co.th", "hostname": "web-prod-01",
                         "admin_user": "sysadmin", "db_name": "acme_erp", "internal_subnet": "10.20.0"},
        "scenarios": {"web": ["web-backup-api"], "shell": "linux-server"},
        "web": {"host": "127.0.0.1", "port": 8084, "log_path": "web.jsonl",
                "trusted_proxies": ["127.0.0.1/32"], "upstream": upstream},
    }
    path = root / "rabbit-hole.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


class ForwardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeUpstream)
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        host, port = self.upstream.server_address
        config = load(write_config(Path(self.tmp.name), f"http://{host}:{port}"))
        self.engine = WebEngine(config)

    def tearDown(self):
        self.upstream.shutdown(); self.upstream.server_close(); self.tmp.cleanup()

    def handle(self, method, path, body=b""):
        return self.engine.handle(method, path, {"host": "192.168.56.10"}, body,
                                  ("192.168.56.80", 5000), ("10.10.10.2", 8084))

    def test_home_comes_from_upstream(self):
        resp = self.handle("GET", "/")
        self.assertEqual(resp.status, 200)
        self.assertIn(b"Acme Logistics home", resp.body)
        self.assertEqual(resp.event["action"], "proxy")
        self.assertIsNone(resp.event["node_id"])

    def test_unknown_path_served_by_upstream_404(self):
        resp = self.handle("GET", "/company/profile")
        self.assertEqual(resp.status, 404)
        self.assertIn(b"not found", resp.body)
        self.assertEqual(resp.event["action"], "proxy")

    def test_bait_path_still_served_by_rabbit_hole(self):
        resp = self.handle("GET", "/backup/")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.event["node_id"], "backup-index")
        self.assertNotIn(b"Acme Logistics home", resp.body)

    def test_no_anonymous_session_cookie_with_upstream(self):
        # The real site sets no cookie for anonymous visitors; neither may the decoy.
        for path in ("/", "/about", "/robots.txt", "/backup/"):
            resp = self.handle("GET", path)
            self.assertNotIn("PHPSESSID", resp.headers.get("Set-Cookie", ""), path)

    def test_upstream_down_returns_502(self):
        self.upstream.shutdown(); self.upstream.server_close()
        resp = self.handle("GET", "/")
        self.assertEqual(resp.status, 502)
        self.assertEqual(resp.event["action"], "proxy_error")

    def test_without_upstream_landing_is_served(self):
        config = load(write_config(Path(self.tmp.name), None) if False else self._no_upstream())
        engine = WebEngine(config)
        resp = engine.handle("GET", "/", {"host": "x"}, b"", ("192.168.56.81", 5000), ("10.10.10.2", 8084))
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.event["action"], "open_page")

    def _no_upstream(self):
        config = {
            "project_root": "..", "enabled": True,
            "organization": {"name": "Acme Logistics", "short_name": "acme",
                             "domain": "acme-logistics.co.th", "hostname": "web-prod-01",
                             "admin_user": "sysadmin", "db_name": "acme_erp", "internal_subnet": "10.20.0"},
            "scenarios": {"web": ["web-backup-api"], "shell": "linux-server"},
            "web": {"host": "127.0.0.1", "port": 8084, "log_path": "web.jsonl",
                    "trusted_proxies": ["127.0.0.1/32"]},
        }
        path = Path(self.tmp.name) / "no-upstream.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
