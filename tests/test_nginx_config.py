from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class NginxConfigTests(unittest.TestCase):
    def test_template_requires_separate_real_web_endpoint(self):
        template = (PROJECT_ROOT / "defender/nginx/adaptive-honeypot.conf.template").read_text(
            encoding="utf-8"
        )
        self.assertIn("http://__REAL_WEB_IP__:__REAL_WEB_PORT__", template)
        self.assertNotIn("http://127.0.0.1:8080", template)

    def test_template_prefilters_risky_first_request(self):
        template = (PROJECT_ROOT / "defender/nginx/adaptive-honeypot.conf.template").read_text(
            encoding="utf-8"
        )
        # The IP map no longer decides alone; it feeds the final profile.
        self.assertIn("map $remote_addr $adaptive_ip_profile {", template)
        self.assertIn('map "$trap_prefilter:$adaptive_ip_profile" $adaptive_profile {', template)
        # An engine decision always wins; a prefilter hit only replaces "real".
        self.assertIn("default  $adaptive_ip_profile;", template)
        self.assertIn('"1:real" __PREFILTER_PROFILE__;', template)
        # Each prefilter pattern mirrors a rule the engine redirects on one alert.
        for pattern in ('"~*\\.htpasswd"', '"~*union.+select.+(;|%3b)"',
                        '"~\\(Nikto"', '"~^sqlmap"', '"~Nmap NSE"'):
            self.assertIn(pattern, template)
        # Rules the engine only monitors must not be prefiltered.
        for pattern in (".env", "etc/passwd", "masscan"):
            self.assertNotIn(f'"~*{pattern}', template)
            self.assertNotIn(f'"~{pattern}', template)
        # The access log records whether the prefilter decided the request.
        self.assertEqual(template.count('"prefilter":$trap_prefilter'), 2)

    def test_generated_example_uses_confirmed_backends(self):
        rendered = (PROJECT_ROOT / "defender/nginx/generated/adaptive-honeypot.http.conf").read_text(
            encoding="utf-8"
        )
        self.assertIn("real        http://10.10.10.3:8080;", rendered)
        self.assertIn("wordpress   http://10.10.10.2:8081;", rendered)
        self.assertIn("phpmyadmin  http://10.10.10.2:8082;", rendered)
        self.assertIn("proxy_connect_timeout 5s;", rendered)
        self.assertIn("proxy_read_timeout 30s;", rendered)


if __name__ == "__main__":
    unittest.main()
