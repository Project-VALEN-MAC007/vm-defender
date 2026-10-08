import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from defender.dashboard.scope import RuleStore
from defender.suricata.apply_rules import apply

RULE = 'alert http any any -> any any (msg:"TRAP LOCAL test"; classtype:web-application-attack; sid:9900001; rev:1;)'


def fake(results):
    calls = []
    def run(command):
        calls.append(list(command))
        code = results.get(command[0], 0)
        return subprocess.CompletedProcess(command, code, "", "line1\nE: bad rule" if code else "")
    return run, calls


class RuleStoreHelperModeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.active = root / "etc" / "active.rules"
        self.active.parent.mkdir()
        self.active.write_text("# active\n", encoding="utf-8")
        self.apply_dir = root / "apply"
        self.apply_dir.mkdir()
        self.store = RuleStore(self.active, root / "backups", self.apply_dir, direct_edit=False)

    def tearDown(self):
        self.tmp.cleanup()

    def test_edit_goes_to_pending_and_requests_apply(self):
        result = self.store.change({"action": "add", "rule": RULE})
        self.assertEqual(result["activation"], "pending")
        self.assertEqual(self.active.read_text(), "# active\n")
        self.assertIn("sid:9900001", (self.apply_dir / "pending.rules").read_text())
        self.assertTrue((self.apply_dir / "request").exists())
        self.assertEqual(self.store.source(), self.apply_dir / "pending.rules")
        self.assertEqual(self.store.apply_status()["state"], "waiting")

    def test_without_helper_live_edit_is_refused(self):
        store = RuleStore(self.active, self.apply_dir, None, direct_edit=False)
        self.assertFalse(store.editable)
        with self.assertRaises(ValueError):
            store.change({"action": "add", "rule": RULE})

    def test_helper_installs_and_clears_pending(self):
        self.store.change({"action": "add", "rule": RULE})
        run, calls = fake({})
        outcome = apply(self.apply_dir / "pending.rules", self.active, Path("/etc/suricata/suricata.yaml"),
                        self.apply_dir / "result.json", run)
        self.assertEqual(outcome["state"], "applied")
        self.assertIn("sid:9900001", self.active.read_text())
        self.assertFalse((self.apply_dir / "pending.rules").exists())
        self.assertEqual(calls[0][:2], ["suricata", "-T"])
        self.assertEqual(self.store.apply_status()["state"], "applied")

    def test_helper_rejects_rules_that_fail_suricata_test(self):
        self.store.change({"action": "add", "rule": RULE})
        run, _ = fake({"suricata": 1})
        outcome = apply(self.apply_dir / "pending.rules", self.active, Path("x"), self.apply_dir / "result.json", run)
        self.assertEqual((outcome["state"], outcome["step"]), ("failed", "syntax_test"))
        self.assertEqual(self.active.read_text(), "# active\n")
        self.assertIn("bad rule", json.loads((self.apply_dir / "result.json").read_text())["detail"])

    def test_helper_restores_previous_rules_when_reload_fails(self):
        self.store.change({"action": "add", "rule": RULE})
        run, _ = fake({"suricatasc": 1, "systemctl": 1})
        outcome = apply(self.apply_dir / "pending.rules", self.active, Path("x"), self.apply_dir / "result.json", run)
        self.assertEqual((outcome["state"], outcome["step"]), ("failed", "reload"))
        self.assertEqual(self.active.read_text(), "# active\n")


if __name__ == "__main__":
    unittest.main()
