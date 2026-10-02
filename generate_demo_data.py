"""Generate synthetic dashboard data without changing real evidence or users."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random


ROOT = Path(__file__).resolve().parent
SCENARIOS = [
    ("http", 80, "SQL injection attempt", "Web Application Attack", 1, "/products?id=1%27", "redirect_web", "snare"),
    ("http", 80, "Cross-site scripting attempt", "Web Application Attack", 2, "/search?q=%3Cscript%3E", "redirect_web", "snare"),
    ("http", 80, "Directory traversal attempt", "Web Application Attack", 1, "/../../etc/passwd", "redirect_web", "snare"),
    ("http", 80, "WordPress login brute force", "Attempted Administrator Privilege Gain", 2, "/wp-login.php", "redirect_web", "wordpress"),
    ("http", 80, "phpMyAdmin discovery", "Web Application Attack", 2, "/phpmyadmin/", "redirect_web", "phpmyadmin"),
    ("http", 80, "Automated sensitive file discovery", "Web Application Attack", 2, "/.env", "redirect_web", "snare"),
    ("ssh", 22, "SSH authentication brute force", "Attempted Administrator Privilege Gain", 1, "", "redirect_ssh", "cowrie"),
    ("ssh", 22, "SSH service enumeration", "Detection of a Network Scan", 3, "", "monitor", "none"),
    ("telnet", 23, "Telnet credential guessing", "Attempted Administrator Privilege Gain", 1, "", "redirect_telnet", "telnet"),
    ("tls", 443, "Suspicious TLS client fingerprint", "Potentially Bad Traffic", 2, "", "monitor", "none"),
    ("dns", 53, "High-volume DNS queries", "Potentially Bad Traffic", 2, "", "monitor", "none"),
    ("tcp", 445, "TCP port scan", "Detection of a Network Scan", 2, "", "monitor", "none"),
    ("http", 80, "Unusual HTTP user agent", "Misc activity", 3, "/", "allow", "none"),
    ("udp", 161, "UDP service discovery", "Detection of a Network Scan", 3, "", "monitor", "none"),
    ("icmp", 0, "ICMP host discovery", "Detection of a Network Scan", 3, "", "allow", "none"),
]


def seed_demo_candidate(directory: Path) -> None:
    from defender.validation.pipeline import validate
    state_path = directory / "dashboard-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    if "demo-sensitive-file" in state.get("candidates", {}):
        return
    count = sum(json.loads(line).get("http", {}).get("url") == "/.env"
                for line in (directory / "eve.json").read_text(encoding="utf-8").splitlines())
    candidate = {"rule_id": "demo-sensitive-file", "version": "1.0.0", "expected_sid": 9901101,
                 "evidence": f"evidence/demo/eve.json: {count} simulated requests to /.env",
                 "confidence": .85, "reviewer": "demo-generator", "status": "candidate",
                 "rule": 'alert http any any -> any any (msg:"TRAP DEMO sensitive file probe"; flow:established,to_server; http.uri; content:"/.env"; classtype:web-application-attack; metadata:severity medium; threshold:type limit, track by_src, count 1, seconds 60; sid:9901101; rev:1;)'}
    path = directory / "candidate-sensitive-file.json"
    path.write_text(json.dumps(candidate, indent=2), encoding="utf-8")
    report = validate(path, directory / "rules.rules", ROOT / "tests/fixtures/baseline.json")
    state.setdefault("candidates", {})[candidate["rule_id"]] = {**candidate, "status": "pending", "test_results": report}
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def generate(alert_count: int, decision_count: int, seed: int) -> dict:
    rng = random.Random(seed)
    now = datetime.now(timezone.utc) - timedelta(seconds=5)
    directory = ROOT / "evidence/demo"
    directory.mkdir(parents=True, exist_ok=True)
    # Documentation IP ranges prevent synthetic records identifying real hosts.
    sources = [f"{prefix}.{suffix}" for prefix in ("192.0.2", "198.51.100", "203.0.113")
               for suffix in range(1, 255)]
    records = []
    for index in range(alert_count):
        bucket = rng.choices((1, 7, 30, 45), (35, 30, 25, 10))[0]
        start = {1: 0, 7: 1, 30: 7, 45: 30}[bucket]
        stamp = now - timedelta(seconds=rng.uniform(start * 86400, bucket * 86400))
        scenario_id = rng.randrange(len(SCENARIOS))
        protocol, port, label, category, severity, url, action, profile = SCENARIOS[scenario_id]
        source = rng.choice(sources[:60] if rng.random() < .65 else sources)
        event = {
            "timestamp": stamp.isoformat(), "event_type": "alert", "flow_id": 9000000 + index,
            "src_ip": source, "src_port": rng.randint(1024, 65535), "dest_ip": "192.0.2.254",
            "dest_port": port, "proto": {"dns": "UDP", "udp": "UDP", "icmp": "ICMP"}.get(protocol, "TCP"),
            "app_proto": protocol, "demo": True,
            "alert": {"signature_id": 9900000 + scenario_id, "signature": "DEMO: " + label,
                      "category": category, "severity": severity, "action": "allowed"}}
        if protocol == "http":
            event["http"] = {"hostname": "trap-demo.example", "url": url,
                             "http_method": "POST" if "login" in url else "GET",
                             "http_user_agent": rng.choice(["DEMO Security Scanner", "Mozilla/5.0 (DEMO)", "DEMO curl/8.0"])}
        records.append((stamp, event, action, profile))
    records.sort(key=lambda entry: entry[0])
    with (directory / "eve.json").open("w", encoding="utf-8") as stream:
        for _, event, _, _ in records:
            stream.write(json.dumps(event) + "\n")
    selected = sorted(rng.sample(records, min(decision_count, len(records))), key=lambda entry: entry[0])
    actions = Counter()
    session_rows = []
    with (directory / "decisions.jsonl").open("w", encoding="utf-8") as stream:
        for index, (stamp, event, action, profile) in enumerate(selected):
            severity = event["alert"]["severity"]
            score = round(rng.uniform(*{1: (70, 99), 2: (35, 79), 3: (5, 34)}[severity]), 1)
            actions[action] += 1
            if action.startswith("redirect") and rng.random() < .8:
                first = stamp + timedelta(seconds=rng.randint(1, 8))
                last = min(now, first + timedelta(seconds=rng.randint(25, 1500)))
                if last >= first:
                    session_rows.append({"session_id": f"demo-session-{index:06d}", "decision_id": f"demo-{index:06d}",
                                         "profile": profile, "source_ip": event["src_ip"], "first_action": first.isoformat(),
                                         "last_action": last.isoformat(), "actions": rng.randint(2, 40), "demo": True})
            stream.write(json.dumps({
                "event_id": f"demo-{index:06d}", "start_time": stamp.isoformat(),
                "source_ip": event["src_ip"], "protocol": event["app_proto"],
                "signature_id": event["alert"]["signature_id"], "severity": severity,
                "risk_score": score, "action": action, "profile": profile,
                "reason": f"DEMO synthetic scenario: {event['alert']['signature']}; risk={score}",
                "expiry": (stamp + timedelta(minutes=30)).isoformat(), "dry_run": True, "demo": True}) + "\n")
    (directory / "honeypot.jsonl").write_text(''.join(json.dumps(row) + "\n" for row in session_rows), encoding="utf-8")
    (directory / "status.json").write_text(json.dumps({
        "demo": "ข้อมูลจำลองสำหรับเดโม่ — สถานะบริการและเหตุการณ์ไม่ใช่ข้อมูลจากระบบจริง",
        "suricata": "active", "nginx": "active", "decision_engine": "active"
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    config = json.loads((ROOT / "config/mimic.json").read_text(encoding="utf-8"))
    config["dashboard"]["maximum_rows"] = max(alert_count, decision_count)
    config["paths"].update({"eve_paths": ["evidence/demo/eve.json"],
                            "decisions": "evidence/demo/decisions.jsonl", "status": "evidence/demo/status.json"})
    config["paths"].update({"honeypot_paths": ["evidence/demo/honeypot.jsonl"],
                            "dashboard_state": "evidence/demo/dashboard-state.json", "engine_config": "evidence/demo/engine.json"})
    config["demo_mode"] = True
    config["rules"]["allow_deploy"] = False
    if not (directory / "rules.rules").exists():
        (directory / "rules.rules").write_bytes((ROOT / "defender/suricata/rules/et-open-selected.rules").read_bytes())
    if not (directory / "engine.json").exists():
        (directory / "engine.json").write_bytes((ROOT / "defender/decision_engine/config/lab.json").read_bytes())
    config["rules"]["active_rules"] = "evidence/demo/rules.rules"
    config["rules"]["backup_dir"] = "evidence/demo/rule-backups"
    config["security"]["require_totp"] = False
    config["security"]["force_default_password_change"] = False
    (ROOT / "config/mimic.demo.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    summary = {"synthetic": True, "generated_at": now.isoformat(), "alerts": alert_count,
               "decisions": len(selected), "source_ips": len({entry[1]["src_ip"] for entry in records}),
               "days": 45, "honeypot_sessions": len(session_rows), "actions": dict(actions), "seed": seed}
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    seed_demo_candidate(directory)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alerts", type=int, default=18000)
    parser.add_argument("--decisions", type=int, default=12000)
    parser.add_argument("--seed", type=int, default=6238)
    args = parser.parse_args()
    if not 1 <= args.decisions <= args.alerts <= 100000:
        parser.error("require 1 <= decisions <= alerts <= 100000")
    print(json.dumps(generate(args.alerts, args.decisions, args.seed), indent=2))
