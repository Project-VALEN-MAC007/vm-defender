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

    def test_generated_example_uses_confirmed_backends(self):
        rendered = (PROJECT_ROOT / "defender/nginx/generated/adaptive-honeypot.http.conf").read_text(
            encoding="utf-8"
        )
        self.assertIn("real        http://10.10.10.3:8080;", rendered)
        self.assertIn("wordpress   http://10.10.10.2:8081;", rendered)
        self.assertIn("phpmyadmin  http://10.10.10.2:8082;", rendered)


if __name__ == "__main__":
    unittest.main()
