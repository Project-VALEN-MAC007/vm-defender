"""Round-8 D1/D2: lab isolation rules and Cowrie hardening."""
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
ISO = ROOT / "deploy" / "isolation"


def _service_block(compose: str, name: str) -> str:
    match = re.search(rf"^  {name}:\n(.*?)(?=^  \S|^\S)", compose, re.S | re.M)
    return match.group(1) if match else ""


class IsolationFileTests(unittest.TestCase):
    def test_every_file_replaces_only_its_own_table(self):
        for role in ("honeypot", "web", "defender"):
            text = (ISO / f"{role}.nft").read_text(encoding="utf-8")
            self.assertIn("delete table inet trap_isolation", text, role)
            self.assertNotRegex(text, r"(?m)^\s*flush ruleset", role)

    def test_honeypot_blocks_container_egress_and_lab_connections(self):
        text = (ISO / "honeypot.nft").read_text(encoding="utf-8")
        self.assertIn('iifname "br-*" oifname != "br-*" ct state new counter drop', text)
        self.assertIn("ip daddr { $LAB_NET, $OUTER_NET } ct state new counter drop", text)
        self.assertIn("ip saddr $LAB_NET ip saddr != $DEFENDER ct state new counter drop", text)

    def test_web_and_defender_accept_only_the_defender_or_drop_the_honeypot(self):
        web = (ISO / "web.nft").read_text(encoding="utf-8")
        self.assertEqual(web.count("ip saddr $LAB_NET ip saddr != $DEFENDER ct state new counter drop"), 2)
        defender = (ISO / "defender.nft").read_text(encoding="utf-8")
        self.assertIn("ip saddr $HONEYPOT ct state new counter drop", defender)

    def test_service_loads_before_docker(self):
        unit = (ISO / "trap-isolation.service").read_text(encoding="utf-8")
        self.assertRegex(unit, r"Before=.*docker\.service")
        self.assertIn("ExecStop=/usr/sbin/nft delete table inet trap_isolation", unit)

    def test_cowrie_root_filesystem_is_read_only(self):
        compose = (ROOT / "honeypot" / "docker" / "compose.yaml").read_text(encoding="utf-8")
        cowrie = _service_block(compose, "cowrie")
        self.assertIn("read_only: true", cowrie)
        self.assertIn("- /tmp", cowrie)


@unittest.skipUnless(shutil.which("nft") and shutil.which("unshare"), "needs nft and unshare")
class IsolationNamespaceTests(unittest.TestCase):
    def test_round8_failures_are_blocked_and_required_paths_stay_open(self):
        probe = subprocess.run(["unshare", "-rn", "true"], capture_output=True)
        if probe.returncode != 0:
            self.skipTest("unprivileged user namespaces are not available")
        result = subprocess.run(
            ["unshare", "-rn", "--kill-child", "bash", str(ISO / "netns-test.sh"), str(ISO)],
            capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
        lines = [line for line in result.stdout.splitlines() if line[:4] in ("ok  ", "FAIL")]
        if not lines:
            self.skipTest("namespace setup not supported here: " + result.stderr[-300:])
        self.assertTrue(all(line.startswith("ok") for line in lines), result.stdout)
        self.assertGreaterEqual(len(lines), 30)
