"""Honeypot container watchdog: a broken container is replaced with a new one."""
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("trap_watchdog", ROOT / "honeypot/docker/watchdog.py")
watchdog = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(watchdog)


class Result:
    def __init__(self, code=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = code, stdout, stderr


def listening(*ports):
    return "".join(f"LISTEN 0 50 0.0.0.0:{port} 0.0.0.0:*\n" for port in ports)


class FakeDocker:
    """containers: name -> State dict (absent = missing); ports: pid -> listening ports."""

    def __init__(self, containers, ports, recreate_ok=True):
        self.containers, self.ports, self.recreate_ok = containers, ports, recreate_ok
        self.calls = []

    def __call__(self, command):
        command = list(command)
        self.calls.append(command)
        if command[:2] == ["docker", "inspect"]:
            state = self.containers.get(command[-1])
            return Result(0, json.dumps(state)) if state is not None else Result(1, "", "No such object")
        if command[0] == "nsenter":
            return Result(0, listening(*self.ports.get(int(command[2]), ())))
        if command[:2] == ["docker", "compose"]:
            return Result(0 if self.recreate_ok else 1, "", "" if self.recreate_ok else "pull access denied")
        raise AssertionError(command)

    def recreated(self):
        return [call[-1] for call in self.calls if call[:2] == ["docker", "compose"]]


def running(pid):
    return {"Status": "running", "Running": True, "Restarting": False, "Pid": pid}


HEALTHY = {"cowrie": running(11), "web-honeypot": running(22)}
PORTS = {11: (2222, 2223), 22: (8084,)}


def fake_proc(root, containers):
    """/proc and cgroup v2 tree: containers maps main pid -> {pid: state}."""
    proc, cgroup = root / "proc", root / "cgroup"
    for main, members in containers.items():
        scope = cgroup / "system.slice" / f"docker-{main}.scope"
        scope.mkdir(parents=True, exist_ok=True)
        (scope / "cgroup.procs").write_text("".join(f"{pid}\n" for pid in members))
        for pid, state in members.items():
            entry = proc / str(pid)
            entry.mkdir(parents=True, exist_ok=True)
            (entry / "stat").write_text(f"{pid} (twistd) {state} 1 {pid} {pid} 0 -1\n")
            (entry / "cgroup").write_text(f"0::/system.slice/docker-{main}.scope\n")
    return proc, cgroup


def set_state(root, pid, state):
    (root / "proc" / str(pid) / "stat").write_text(f"{pid} (twistd) {state} 1 {pid} {pid} 0 -1\n")


class WatchdogTests(unittest.TestCase):
    def make(self, root, docker, failures=3):
        proc, cgroup = fake_proc(root, {11: {11: "S", 12: "S"}, 22: {22: "S"}})
        return watchdog.Watchdog(root / "compose.yaml", "trap-honeypot", root / "state.json",
                                 root / "watchdog.jsonl", failures, run=docker,
                                 now=lambda: datetime(2026, 10, 10, 9, tzinfo=timezone.utc),
                                 proc_root=proc, cgroup_root=cgroup)

    def test_stopped_process_is_replaced_although_ports_still_listen(self):
        # SIGSTOP keeps sockets in LISTEN; only the process state shows the hang.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); docker = FakeDocker(dict(HEALTHY), dict(PORTS))
            dog = self.make(root, docker, failures=3)
            set_state(root, 12, "T")  # a child of the cowrie container, not its main pid
            dog.run_once(); dog.run_once()
            self.assertEqual(docker.recreated(), [])
            dog.run_once()
            self.assertEqual(docker.recreated(), ["cowrie"])
            self.assertEqual({e["reason"] for e in self.events(root)}, {"process_stopped:12"})

    def test_freshly_started_container_gets_time_to_listen(self):
        # Round 5: Cowrie needed ~57 s to listen after a replacement; counting
        # that as unhealthy could replace it again before it ever came up.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            containers = dict(HEALTHY)
            containers["cowrie"] = dict(running(11), StartedAt="2026-10-10T08:59:30.123456789Z")  # 30 s old
            docker = FakeDocker(containers, {11: (), 22: (8084,)})
            dog = self.make(root, docker, failures=1)
            dog.run_once(); dog.run_once(); dog.run_once()
            self.assertEqual(docker.recreated(), [])
            self.assertEqual(self.events(root), [])
            containers["cowrie"]["StartedAt"] = "2026-10-10T08:57:00Z"  # 3 min old: grace over
            dog.run_once()
            self.assertEqual(docker.recreated(), ["cowrie"])

    def test_stopped_process_is_not_excused_by_the_grace_period(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            containers = dict(HEALTHY)
            containers["cowrie"] = dict(running(11), StartedAt="2026-10-10T08:59:50Z")
            docker = FakeDocker(containers, dict(PORTS))
            dog = self.make(root, docker, failures=1)
            set_state(root, 12, "T")
            dog.run_once()
            self.assertEqual(docker.recreated(), ["cowrie"])

    def test_replacement_uses_a_short_stop_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            containers = dict(HEALTHY); containers.pop("cowrie")
            docker = FakeDocker(containers, dict(PORTS))
            self.make(root, docker).run_once()
            compose = [c for c in docker.calls if c[:2] == ["docker", "compose"]][0]
            self.assertEqual(compose[compose.index("--timeout") + 1], "3")

    def test_docker_start_time_parsing(self):
        parsed = watchdog.started_at({"StartedAt": "2026-10-10T13:36:23.862763123Z"})
        self.assertEqual(parsed, datetime(2026, 10, 10, 13, 36, 23, 862763, tzinfo=timezone.utc))
        self.assertIsNone(watchdog.started_at({"StartedAt": "0001-01-01T00:00:00Z"}))
        self.assertIsNone(watchdog.started_at({}))

    def test_without_cgroup_view_checks_the_main_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "proc" / "11"; proc.mkdir(parents=True)
            (proc / "stat").write_text("11 (twistd) t 1 11 11 0 -1\n")
            self.assertEqual(watchdog.stopped_processes(11, root / "proc", root / "no-cgroup"), [11])

    def events(self, root):
        path = root / "watchdog.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_healthy_containers_are_left_alone(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); docker = FakeDocker(dict(HEALTHY), dict(PORTS))
            self.assertEqual(self.make(root, docker).run_once(), [])
            self.assertEqual(docker.recreated(), [])
            self.assertEqual(self.events(root), [])

    def test_missing_stopped_and_crash_looping_are_replaced_at_once(self):
        cases = {
            "missing": None,
            "paused": {"Status": "paused", "Running": True, "Paused": True, "Pid": 11},
            "exited": {"Status": "exited", "Running": False, "Restarting": False, "Pid": 0},
            "dead": {"Status": "dead", "Running": False, "Restarting": False, "Pid": 0},
            "restarting": {"Status": "restarting", "Running": True, "Restarting": True, "Pid": 0},
        }
        for label, state in cases.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                containers = dict(HEALTHY)
                if state is None:
                    containers.pop("cowrie")
                else:
                    containers["cowrie"] = state
                docker = FakeDocker(containers, dict(PORTS))
                actions = self.make(root, docker).run_once()
                self.assertEqual(docker.recreated(), ["cowrie"])
                self.assertTrue(actions[0]["ok"])
                compose = [c for c in docker.calls if c[:2] == ["docker", "compose"]][0]
                self.assertIn("--force-recreate", compose)
                self.assertIn("--no-deps", compose)
                self.assertIn("--no-build", compose)

    def test_hung_container_is_replaced_after_consecutive_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = FakeDocker(dict(HEALTHY), {11: (2222,), 22: (8084,)})  # Telnet 2223 not listening
            dog = self.make(root, docker, failures=3)
            dog.run_once(); dog.run_once()
            self.assertEqual(docker.recreated(), [])
            dog.run_once()
            self.assertEqual(docker.recreated(), ["cowrie"])
            reasons = [e["reason"] for e in self.events(root)]
            self.assertEqual(reasons, ["not_listening:2223"] * 3)
            self.assertEqual(json.loads((root / "state.json").read_text()), {})

    def test_recovery_resets_the_counter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = FakeDocker(dict(HEALTHY), {11: (2222, 2223), 22: ()})
            dog = self.make(root, docker, failures=3)
            dog.run_once(); dog.run_once()
            docker.ports[22] = (8084,)
            dog.run_once()
            docker.ports[22] = ()
            dog.run_once(); dog.run_once()
            self.assertEqual(docker.recreated(), [])
            self.assertIn("recovered", [e["event"] for e in self.events(root)])

    def test_failed_replacement_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            containers = dict(HEALTHY); containers.pop("web-honeypot")
            docker = FakeDocker(containers, dict(PORTS), recreate_ok=False)
            actions = self.make(root, docker).run_once()
            self.assertFalse(actions[0]["ok"])
            self.assertIn("pull access denied", actions[0]["detail"])

    def test_never_connects_to_the_decoys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); docker = FakeDocker(dict(HEALTHY), dict(PORTS))
            self.make(root, docker).run_once()
            self.assertTrue(all(c[0] in {"docker", "nsenter"} for c in docker.calls))


class ComposeFileTests(unittest.TestCase):
    def test_compose_has_one_container_per_decoy(self):
        text = (ROOT / "honeypot/docker/compose.yaml").read_text(encoding="utf-8")
        for needle in ("container_name: cowrie", "container_name: web-honeypot", "restart: unless-stopped",
                       ":2222:2222", ":2223:2223", ":8084:8084", "/var/log/cowrie:", "/var/log/trap:/var/log/trap",
                       "/var/lib/trap/cowrie-fs:/cowrie/trapfs:ro", "no-new-privileges:true", "RABBIT_UID"):
            self.assertIn(needle, text)
        dockerfile = (ROOT / "honeypot/docker/Dockerfile.webhoneypot").read_text(encoding="utf-8")
        self.assertIn("USER 10001", dockerfile)
        self.assertIn("COPY defender/rabbit_hole", dockerfile)

    def test_web_image_runs_the_decoy_from_its_package_only(self):
        # The image copies only defender/rabbit_hole; it must not import other project packages.
        for path in (ROOT / "defender/rabbit_hole").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("from defender.", text.replace("from defender.rabbit_hole", ""), path.name)
            self.assertNotIn("from ..", text, path.name)


if __name__ == "__main__":
    unittest.main()
