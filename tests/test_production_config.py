import json
from pathlib import Path
import tempfile
import unittest

from defender.validation.production import assess_config


class ProductionConfigTests(unittest.TestCase):
    def test_placeholders_block_production_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "mimic.json"
            config.write_text(json.dumps({
                "project_root": ".",
                "network": {
                    "management_interface": "CHANGE_ME",
                    "outer_interface": "CHANGE_ME",
                    "inner_interface": "CHANGE_ME",
                    "outer_ip": "192.168.56.10",
                    "inner_ip": "10.10.10.1",
                },
                "security": {"users_file": "users.json"},
            }), encoding="utf-8")
            report = assess_config(config)
            checks = {item["name"]: item for item in report["checks"]}
            self.assertFalse(report["ready"])
            self.assertEqual(checks["network_interfaces_configured"]["status"], "blocked")
            self.assertEqual(checks["lab_config_dry_run"]["status"], "passed")


if __name__ == "__main__":
    unittest.main()
