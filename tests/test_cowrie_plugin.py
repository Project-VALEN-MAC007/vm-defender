"""Jev-driven Rabbit Hole for SSH/Telnet: shell pool, Cowrie plugin, install and planner."""
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import pickle
import tempfile
import unittest

from defender.rabbit_hole.config import load
from defender.rabbit_hole.cowrie_install import install
from defender.rabbit_hole.planner import Planner
from defender.rabbit_hole.shell import events_from_cowrie, render_files, shell_pool_bundle

from tests.test_rabbit_pool import FakeJev, write_config

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "honeypot/cowrie/traprabbit.py"
ATTACKER = "192.0.2.60"


def load_plugin():
    spec = importlib.util.spec_from_file_location("traprabbit_under_test", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CowrieTelnetTransport:
    transportId = "a1b2c3d4e5f6"


class SSHTransport:
    transportId = "0f0e0d0c0b0a"


class PT:
    def __init__(self, transport):
        self.transport = transport


def fake_classes():
    class FakeFS:
        def file_contents(self, target):
            return b"STATIC"

        def get_path(self, path, follow_symlinks=True):
            return ["listing-of-" + path]

    class FakeProtocol:
        def __init__(self, ip, transport):
            self.fs = FakeFS()
            self.realClientIP = ip
            self.sessionno = 7
            self.pt = PT(transport)

        def connectionMade(self):
            return "made"
    return FakeFS, FakeProtocol


class ShellPoolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = load(write_config(self.root))
        self.bundle = shell_pool_bundle(self.config)
        self.bundle_path = self.root / "trap-shell-pool.json"
        self.bundle_path.write_text(json.dumps(self.bundle), encoding="utf-8")
        self.plan_path = self.root / "plan.json"
        self.log_path = self.root / "shell.jsonl"
        self.plugin = load_plugin()
        self.engine = self.plugin.Engine(str(self.bundle_path), str(self.plan_path), str(self.log_path),
                                         clock=lambda: 1795000000.0)
        self.fs_cls, self.proto_cls = fake_classes()
        self.assertTrue(self.plugin.install_patches(self.fs_cls, self.proto_cls, self.engine))
        self.items = self.bundle["items"]

    def tearDown(self):
        self.tmp.cleanup()

    def session(self, ip=ATTACKER, transport=None):
        protocol = self.proto_cls(ip, transport or SSHTransport())
        self.assertEqual(protocol.connectionMade(), "made")
        return protocol

    def events(self):
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()]

    def test_bundle_is_valid_self_contained_and_secret_free(self):
        self.assertEqual(self.config.problems(), [])
        self.assertIn("sh-notes", self.items)
        self.assertIn("{{clue:conf}}", self.items["sh-notes"]["template"])
        self.assertNotIn("{{org.", json.dumps(self.bundle))
        self.assertNotIn(self.config.secret().decode(), json.dumps(self.bundle))
        text = PLUGIN.read_text(encoding="utf-8")
        self.assertNotIn("import defender", text)
        self.assertNotIn("from defender", text)
        static = render_files(self.config)
        self.assertTrue(all("{{clue" not in content for _, content in static.values()))

    def test_fallback_clues_per_session_and_followed_depth(self):
        protocol = self.session()
        notes = self.items["sh-notes"]["path"]
        content = protocol.fs.file_contents(notes).decode()
        self.assertNotIn("{{clue", content)
        first = self.events()[-1]
        self.assertEqual((first["event"], first["node_id"], first["protocol"]), ("rabbit_hole.shell", "sh-notes", "ssh"))
        self.assertEqual(first["session_id"], SSHTransport.transportId)  # same id as cowrie.json
        choice = {c["slot"]: c for c in first["clue_choices"]}["conf"]
        self.assertEqual(choice["by"], "fallback")
        target = self.items[choice["items"][0]]["path"]
        self.assertIn(target, content)
        protocol.fs.file_contents(target)
        followed = self.events()[-1]
        self.assertTrue(followed["followed_clue"])
        self.assertEqual((followed["clue_from"], followed["depth"], followed["clue_by"]), ("sh-notes", 2, "fallback"))
        self.assertEqual(protocol.fs.file_contents(notes).decode(), content)  # frozen for the session

    def test_jev_plan_and_telnet(self):
        self.plan_path.write_text(json.dumps({"ips": {ATTACKER: {"choices": {
            "sh-notes.conf": {"items": ["sh-mysql-cnf"], "confidence": 0.83}}}}}), encoding="utf-8")
        protocol = self.session(transport=CowrieTelnetTransport())
        content = protocol.fs.file_contents(self.items["sh-notes"]["path"]).decode()
        self.assertIn(self.items["sh-mysql-cnf"]["path"], content)
        event = self.events()[-1]
        self.assertEqual((event["protocol"], event["session_id"]), ("telnet", "a1b2c3d4e5f6"))
        conf = {c["slot"]: c for c in event["clue_choices"]}["conf"]
        self.assertEqual((conf["by"], conf["confidence"]), ("jev", 0.83))
        protocol.fs.file_contents(self.items["sh-mysql-cnf"]["path"])
        self.assertEqual(self.events()[-1]["clue_by"], "jev")
        other = self.session(ip="198.51.100.9")
        other.fs.file_contents(self.items["sh-notes"]["path"])
        self.assertEqual({c["by"] for c in self.events()[-1]["clue_choices"]}, {"fallback"})

    def test_untouched_paths_and_listings_keep_cowrie_behaviour(self):
        protocol = self.session()
        self.assertEqual(protocol.fs.file_contents("/etc/passwd"), b"STATIC")
        protocol.cwd = "/home/" + self.config.organization["admin_user"]
        self.assertNotEqual(protocol.fs.file_contents("notes.txt"), b"STATIC")  # relative to the shell cwd
        no_context = self.fs_cls()
        self.assertEqual(no_context.file_contents(self.items["sh-notes"]["path"]), b"STATIC")
        dumps = self.items["sh-dumps-dir"]["path"]
        self.assertEqual(protocol.fs.get_path(dumps), ["listing-of-" + dumps])
        self.assertEqual(self.events()[-1]["action"], "list_directory")
        # A missing bundle turns the plugin into a no-op.
        self.bundle_path.unlink()
        self.assertEqual(self.session().fs.file_contents(self.items["sh-notes"]["path"]), b"STATIC")

    def test_depth_limit_drops_clue_lines(self):
        self.bundle["max_depth"] = 1
        self.bundle_path.write_text(json.dumps(self.bundle), encoding="utf-8")
        content = self.session().fs.file_contents(self.items["sh-notes"]["path"]).decode()
        self.assertNotIn("rotate DB password", content)
        self.assertIn("vpn:", content)

    def test_cowrie_log_only_adds_connection_end_in_jev_mode(self):
        rows = events_from_cowrie([
            {"eventid": "cowrie.command.input", "session": "s1", "input": "cat notes.txt",
             "timestamp": "2026-11-19T03:00:00Z", "src_ip": ATTACKER},
            {"eventid": "cowrie.session.closed", "session": "s1", "duration": 12.5,
             "timestamp": "2026-11-19T03:00:10Z", "src_ip": ATTACKER}], self.config)
        self.assertEqual([r["action"] for r in rows], ["session_closed"])
        self.assertEqual(rows[0]["connection_seconds"], 12.5)

    def test_install_writes_bundle_next_to_fs_pickle(self):
        fs_dir = self.root / "cowrie-fs"
        (fs_dir / "honeyfs").mkdir(parents=True)
        pickle_path = fs_dir / "fs.pickle"
        pickle_path.write_bytes(pickle.dumps(["", 1, 0, 0, 4096, 0o40755, 0, [], None, None]))
        result = install(self.config, pickle_path, fs_dir / "honeyfs", self.root / "state")
        self.assertTrue(result["changed"])
        installed = json.loads((fs_dir / "trap-shell-pool.json").read_text(encoding="utf-8"))
        self.assertEqual(set(installed["items"]), set(self.items))
        notes = self.items["sh-notes"]["path"]
        self.assertTrue((fs_dir / "honeyfs" / notes.lstrip("/")).is_file())
        fixed = load(write_config(self.root, strategy="fixed"))
        install(fixed, pickle_path, fs_dir / "honeyfs", self.root / "state")
        self.assertFalse((fs_dir / "trap-shell-pool.json").exists())


class ShellPlannerTests(unittest.TestCase):
    def test_ssh_redirect_gets_shell_questions(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config = load(write_config(root, ai={"enabled": True}))
            now = datetime(2026, 11, 19, 3, 0, tzinfo=timezone.utc)
            (root / "decisions.jsonl").write_text(json.dumps({
                "start_time": (now - timedelta(seconds=20)).isoformat(), "source_ip": ATTACKER, "protocol": "ssh",
                "signature_id": 2006546, "severity": 2, "risk_score": 45.0, "action": "redirect_ssh"}) + "\n",
                encoding="utf-8")
            fake = FakeJev()
            planner = Planner(config, root / "decisions.jsonl", [], [], root / "plan.json", client=fake,
                              clock=lambda: now)
            planner.run_once()
            questions = fake.calls[0][1]
            asked = " ".join(q["instructions"] for name, q in questions.items() if name != "goal")
            self.assertIn("notes.txt", asked)
            self.assertNotIn("/robots.txt", asked)  # no web questions for an SSH-only attacker
            choices = json.loads((root / "plan.json").read_text())["ips"][ATTACKER]["choices"]
            self.assertTrue(any(key.startswith("sh-") for key in choices))


if __name__ == "__main__":
    unittest.main()
