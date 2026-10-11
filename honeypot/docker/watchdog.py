"""Replace a broken honeypot container with a new one.

Run as root by trap-honeypot-watchdog.timer every 20 seconds on the Honeypot.
Docker's restart policy already restarts a process that exits; this covers
what it does not:

- container missing (removed) or stopped/dead      -> new container at once
- stuck restarting (crash loop)                    -> new container at once
- running but a process in it is stopped (state T),
  or its ports are not listening, for `--failures`
  checks in a row (hung)                           -> new container

A container that started less than `--grace` seconds ago and is not listening
yet is left to finish starting (Cowrie took ~1 minute on the lab VM); counting
it as unhealthy could replace it again before it ever comes up.

"New container" is `docker compose up -d --force-recreate --no-deps <service>`:
a fresh container from the pinned image. Logs live on host bind mounts, so
nothing recorded before the replacement is lost.

Health is read from the container's own network namespace (`ss -ltn` via
nsenter), never by connecting to the decoy: a probe connection would be
logged by Cowrie / the web decoy as a visitor every 20 seconds.

A stopped process keeps its listening sockets, so the port check alone would
miss it; every process in the container's cgroup is checked for state T/t.
A process that is running, listening and deadlocked cannot be told apart from
a healthy one without connecting to it, and is not detected.

Every action is appended as one JSON line to --log.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
from typing import Callable, Sequence

SERVICES: dict[str, tuple[int, ...]] = {
    "cowrie": (2222, 2223),
    "web-honeypot": (8084,),
}

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess"]


def _run(command: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(list(command), capture_output=True, text=True, timeout=60, check=False)


def container_state(name: str, run: Runner) -> dict | None:
    """Docker's State object for the container, or None when it does not exist."""
    result = run(["docker", "inspect", "--format", "{{json .State}}", name])
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except ValueError:
        return None


def listening_ports(pid: int, run: Runner) -> set[int]:
    result = run(["nsenter", "-t", str(pid), "-n", "ss", "-Hltn"])
    ports: set[int] = set()
    if result.returncode != 0:
        return ports
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            local = fields[3]
            try:
                ports.add(int(local.rsplit(":", 1)[1]))
            except (IndexError, ValueError):
                continue
    return ports


def stopped_processes(pid: int, proc_root: Path = Path("/proc"),
                      cgroup_root: Path = Path("/sys/fs/cgroup")) -> list[int]:
    """PIDs in the container's cgroup (v2) that are stopped by a signal or tracer."""
    try:
        lines = (proc_root / str(pid) / "cgroup").read_text(encoding="utf-8").splitlines()
        relative = next(line.split("::", 1)[1] for line in lines if line.startswith("0::"))
        members = (cgroup_root / relative.lstrip("/") / "cgroup.procs").read_text(encoding="utf-8").split()
    except (OSError, StopIteration, IndexError):
        members = [str(pid)]  # no cgroup v2 view: check the main process only
    stopped = []
    for member in members:
        try:
            stat = (proc_root / member / "stat").read_text(encoding="utf-8", errors="replace")
            state = stat.rsplit(")", 1)[1].split()[0]
        except (OSError, IndexError):
            continue  # exited while we looked
        if state in {"T", "t"}:
            stopped.append(int(member))
    return stopped


def started_at(state: dict) -> datetime | None:
    """Docker's StartedAt (RFC 3339 with nanoseconds) as an aware datetime."""
    value = str(state.get("StartedAt") or "")
    if not value or value.startswith("0001-"):
        return None
    value = value.replace("Z", "+00:00")
    main, _, zone = value.partition("+")
    if "." in main:
        head, fraction = main.split(".", 1)
        main = head + "." + fraction[:6]
    try:
        return datetime.fromisoformat(main + ("+" + zone if zone else "+00:00"))
    except ValueError:
        return None


def check(name: str, ports: tuple[int, ...], run: Runner,
          proc_root: Path = Path("/proc"), cgroup_root: Path = Path("/sys/fs/cgroup"),
          now: datetime | None = None, grace: float = 0) -> tuple[str, str]:
    """('ok' | 'starting' | 'replace' | 'unhealthy', reason)."""
    state = container_state(name, run)
    if state is None:
        return "replace", "container_missing"
    status = state.get("Status")
    if status == "restarting" or state.get("Restarting"):
        return "replace", "crash_loop"
    if status != "running" or not state.get("Running"):
        return "replace", f"container_{status or 'unknown'}"
    pid = int(state.get("Pid") or 0)
    if pid <= 0:
        return "unhealthy", "no_pid"
    stopped = stopped_processes(pid, proc_root, cgroup_root)
    if stopped:
        return "unhealthy", "process_stopped:" + ",".join(str(member) for member in stopped)
    missing = [port for port in ports if port not in listening_ports(pid, run)]
    if missing:
        started = started_at(state)
        if grace > 0 and started is not None and now is not None and (now - started).total_seconds() < grace:
            return "starting", "starting:not_listening:" + ",".join(str(port) for port in missing)
        return "unhealthy", "not_listening:" + ",".join(str(port) for port in missing)
    return "ok", "listening"


class Watchdog:
    def __init__(self, compose: Path, project: str, state_path: Path, log_path: Path,
                 failures: int = 3, run: Runner = _run, now: Callable[[], datetime] | None = None,
                 proc_root: Path = Path("/proc"), cgroup_root: Path = Path("/sys/fs/cgroup"),
                 grace: float = 120, stop_timeout: int = 3):
        self.compose, self.project = compose, project
        self.grace, self.stop_timeout = grace, stop_timeout
        self.proc_root, self.cgroup_root = proc_root, cgroup_root
        self.state_path, self.log_path = state_path, log_path
        self.failures, self.run = failures, run
        self.now = now or (lambda: datetime.now(timezone.utc))

    def _load(self) -> dict[str, int]:
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            return {str(key): int(value) for key, value in raw.items()}
        except (OSError, ValueError, AttributeError):
            return {}

    def _save(self, counts: dict[str, int]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(counts), encoding="utf-8")
        os.replace(temporary, self.state_path)

    def _log(self, record: dict) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"time": self.now().isoformat(), **record}, sort_keys=True) + "\n")

    def replace(self, service: str) -> subprocess.CompletedProcess:
        # Short stop timeout: a stopped (SIGSTOP) or hung process never handles
        # SIGTERM, and the decoy holds nothing that needs a graceful shutdown.
        return self.run(["docker", "compose", "-p", self.project, "-f", str(self.compose),
                         "up", "-d", "--no-build", "--force-recreate", "--no-deps",
                         "--timeout", str(self.stop_timeout), service])

    def run_once(self) -> list[dict]:
        counts = self._load()
        actions = []
        for service, ports in SERVICES.items():
            verdict, reason = check(service, ports, self.run, self.proc_root, self.cgroup_root,
                                    self.now(), self.grace)
            if verdict == "starting":
                continue  # neither healthy nor counted: give it time to come up
            if verdict == "ok":
                if counts.pop(service, 0):
                    self._log({"service": service, "event": "recovered", "reason": reason})
                continue
            if verdict == "unhealthy":
                counts[service] = counts.get(service, 0) + 1
                if counts[service] < self.failures:
                    self._log({"service": service, "event": "unhealthy", "reason": reason,
                               "consecutive": counts[service], "replace_at": self.failures})
                    continue
            result = self.replace(service)
            record = {"service": service, "event": "replaced", "reason": reason,
                      "ok": result.returncode == 0,
                      "detail": (result.stderr or result.stdout or "").strip()[-400:]}
            self._log(record)
            actions.append(record)
            counts[service] = 0 if result.returncode == 0 else counts.get(service, 0)
        self._save({key: value for key, value in counts.items() if value})
        return actions


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--compose", default="/opt/trap/honeypot/docker/compose.yaml")
    parser.add_argument("--project", default="trap-honeypot")
    parser.add_argument("--state", default="/run/trap-honeypot-watchdog/state.json")
    parser.add_argument("--log", default="/var/log/trap/honeypot-watchdog.jsonl")
    parser.add_argument("--failures", type=int, default=3)
    parser.add_argument("--grace", type=float, default=120,
                        help="seconds after a container starts before 'not listening' counts")
    parser.add_argument("--stop-timeout", type=int, default=3)
    args = parser.parse_args(argv)
    actions = Watchdog(Path(args.compose), args.project, Path(args.state), Path(args.log),
                       max(1, args.failures), grace=max(0.0, args.grace),
                       stop_timeout=max(0, args.stop_timeout)).run_once()
    return 1 if any(not action["ok"] for action in actions) else 0


if __name__ == "__main__":
    raise SystemExit(main())
