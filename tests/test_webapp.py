"""Company web app: identical public pages for real/decoy, isolated data."""
from http.server import ThreadingHTTPServer
import threading
import unittest
import urllib.request
import urllib.error

from webapp.app import handler_factory, Sessions
from webapp.backends import load as load_backend


def serve(backend_name):
    backend = load_backend(backend_name)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory(backend, Sessions()))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, backend


class Client:
    def __init__(self, base):
        self.base = base
        self.cookie = None

    def request(self, method, path, data=None, follow=False):
        url = self.base + path
        body = None
        headers = {}
        if data is not None:
            body = "&".join(f"{k}={v}" for k, v in data.items()).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if self.cookie:
            headers["Cookie"] = self.cookie
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler) if follow \
            else urllib.request.build_opener(_NoRedirect())
        try:
            resp = opener.open(req)
            status, resp_headers, payload = resp.status, resp.headers, resp.read().decode()
        except urllib.error.HTTPError as err:
            status, resp_headers, payload = err.code, err.headers, err.read().decode()
        set_cookie = resp_headers.get("Set-Cookie")
        if set_cookie and "alsid=" in set_cookie and "Max-Age=0" not in set_cookie:
            self.cookie = set_cookie.split(";", 1)[0]
        return status, resp_headers, payload


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.servers = []

    def tearDown(self):
        for server in self.servers:
            server.shutdown(); server.server_close()

    def client(self, backend_name):
        server, backend = serve(backend_name)
        self.servers.append(server)
        host, port = server.server_address
        return Client(f"http://{host}:{port}"), backend

    def test_public_pages_identical_between_real_and_decoy(self):
        real, _ = self.client("real")
        decoy, _ = self.client("decoy")
        for path in ("/", "/about", "/services", "/news", "/contact", "/login",
                     "/static/site.css", "/news/iso-audit", "/missing-page"):
            rs, _, rbody = real.request("GET", path)
            ds, _, dbody = decoy.request("GET", path)
            self.assertEqual(rs, ds, path)
            self.assertEqual(rbody, dbody, f"body differs for {path}")

    def test_not_found_is_404_on_both(self):
        for name in ("real", "decoy"):
            client, _ = self.client(name)
            status, _, _ = client.request("GET", "/does-not-exist")
            self.assertEqual(status, 404)

    def test_server_header_is_generic(self):
        client, _ = self.client("decoy")
        _, headers, _ = client.request("GET", "/")
        self.assertEqual(headers.get("Server"), "nginx")
        self.assertIsNone(headers.get("X-Powered-By"))

    def test_decoy_login_and_portal_use_fake_data(self):
        client, backend = self.client("decoy")
        status, headers, _ = client.request("POST", "/login",
                                            {"username": "customer", "password": "Welcome2026!"})
        self.assertEqual(status, 303)
        self.assertEqual(headers.get("Location"), "/portal")
        status, _, body = client.request("GET", "/portal")
        self.assertEqual(status, 200)
        self.assertIn("Demo Customer", body)
        self.assertIn("AL-770021", body)

    def test_wrong_password_is_401_and_no_session(self):
        client, _ = self.client("decoy")
        status, _, body = client.request("POST", "/login",
                                         {"username": "customer", "password": "wrong"})
        self.assertEqual(status, 401)
        self.assertIn("Invalid username", body)
        status, _, _ = client.request("GET", "/portal")
        self.assertEqual(status, 303)

    def test_real_and_decoy_accounts_are_disjoint(self):
        _, real_backend = self.client("real")
        _, decoy_backend = self.client("decoy")
        self.assertFalse(set(real_backend.accounts) & set(decoy_backend.accounts))
        # A production credential must not authenticate against the decoy.
        for username, account in real_backend.accounts.items():
            self.assertIsNone(decoy_backend.verify(username, account["password"]))

    def test_contact_form_records_into_backend(self):
        client, backend = self.client("decoy")
        status, _, body = client.request("POST", "/contact",
                                         {"name": "Tester", "email": "t%40example.com", "message": "hi"})
        self.assertEqual(status, 200)
        self.assertIn("Thank you", body)
        self.assertEqual(backend.contact_count(), 1)

    def test_logout_clears_cookie(self):
        client, _ = self.client("decoy")
        client.request("POST", "/login", {"username": "customer", "password": "Welcome2026!"})
        _, headers, _ = client.request("GET", "/logout")
        self.assertIn("Max-Age=0", headers.get("Set-Cookie", ""))

    def test_robots_identical_and_matches_rabbit_hole(self):
        bodies = {}
        for name in ("real", "decoy"):
            status, headers, body = self.client(name)[0].request("GET", "/robots.txt")
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "text/plain; charset=utf-8")
            bodies[name] = body
        self.assertEqual(bodies["real"], bodies["decoy"])
        # Rabbit Hole serves the bait robots node on the honeypot; it must match.
        import json, tempfile, sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent))
        from test_rabbit_forward import write_config
        from defender.rabbit_hole.config import load
        from defender.rabbit_hole.web import WebEngine
        with tempfile.TemporaryDirectory() as tmp:
            engine = WebEngine(load(write_config(Path(tmp), None)))
            resp = engine.handle("GET", "/robots.txt", {"host": "x"}, b"",
                                 ("192.0.2.1", 1), ("10.10.10.2", 8084))
        self.assertEqual(resp.body.decode(), bodies["real"])
        self.assertEqual(resp.headers["Content-Type"], "text/plain; charset=utf-8")

    def test_decoy_accepts_carried_over_session_cookie(self):
        # A session cookie issued by production (unknown here) still opens a portal
        # on the decoy, so a redirected, logged-in visitor is not bounced to login.
        decoy, _ = self.client("decoy")
        decoy.cookie = "alsid=" + "a" * 32
        status, _, body = decoy.request("GET", "/portal")
        self.assertEqual(status, 200)
        self.assertIn("Demo Customer", body)
        real, _ = self.client("real")
        real.cookie = "alsid=" + "a" * 32
        status, headers, _ = real.request("GET", "/portal")
        self.assertEqual(status, 303)
        decoy.cookie = "alsid=not-a-token"
        status, _, _ = decoy.request("GET", "/portal")
        self.assertEqual(status, 303)

    def test_unknown_backend_rejected(self):
        with self.assertRaises(ValueError):
            load_backend("prod")


if __name__ == "__main__":
    unittest.main()
