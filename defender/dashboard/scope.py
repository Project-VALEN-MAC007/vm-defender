"""Dashboard operations and Honeypot session summaries for section 1.3.2.3."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import secrets
import threading


def stamp(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except ValueError:
        return None


def atomic_text(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + secrets.token_hex(6) + ".tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def honeypot_transform(event, path):
    session = event.get("session_id") or event.get("session")
    timestamp = event.get("timestamp") or event.get("first_action")
    if not session or not stamp(timestamp):
        return None
    return {**event, "session_id": str(session), "timestamp": timestamp,
            "source_ip": event.get("source_ip") or event.get("src_ip"),
            "profile": event.get("profile") or ("cowrie" if event.get("eventid", "").startswith("cowrie.") else "web"),
            "source_file": str(path)}


def sessions_from_events(events):
    groups = {}
    for event in events:
        # Dwell means first recorded action through last recorded action; connection
        # and disconnect events alone do not count as an attacker action.
        if event.get("eventid") in {"cowrie.session.connect", "cowrie.session.closed", "cowrie.client.version"}:
            continue
        key = (event.get("profile"), event.get("session_id"), event.get("source_ip"))
        first = stamp(event.get("first_action") or event.get("timestamp"))
        last = stamp(event.get("last_action") or event.get("timestamp"))
        if not first or not last or last < first:
            continue
        item = groups.setdefault(key, {"profile": key[0], "session_id": key[1], "source_ip": key[2],
                                      "first_action": first, "last_action": last,
                                      "decision_id": event.get("decision_id"), "actions": 0})
        item["first_action"] = min(first, item["first_action"])
        item["last_action"] = max(last, item["last_action"])
        item["actions"] += int(event.get("actions", 1))
    return [{**item, "dwell_seconds": (item["last_action"] - item["first_action"]).total_seconds(),
             "first_action": item["first_action"].isoformat(), "last_action": item["last_action"].isoformat()}
            for item in groups.values()]


def extend_analytics(result, alerts, decisions, sessions):
    result["severity_rank"] = [{"source_ip": ip, "count": count} for ip, count in
                               Counter(a.get("src_ip") for a in alerts if str(a.get("severity")) == "1").most_common(10)]
    result["decision_protocols"] = dict(Counter(str(d.get("protocol") or "unknown").upper() for d in decisions))
    result["decision_severities"] = dict(Counter(str(d.get("severity") or "unknown") for d in decisions))
    profiles = defaultdict(list)
    for item in sessions:
        profiles[item["profile"]].append(item["dwell_seconds"])
    result["honeypot_dwell"] = [{"profile": profile, "sessions": len(values),
                                 "average_seconds": round(sum(values) / len(values), 2)}
                                for profile, values in sorted(profiles.items())]
    result["honeypot_sessions"] = len(sessions)
    result["honeypot_telemetry_available"] = bool(sessions)
    return result


def event_notifications(decisions, alerts, sessions):
    by_id = {s["decision_id"]: s for s in sessions if s.get("decision_id")}
    by_source = defaultdict(list)
    for session in sessions:
        by_source[(session["source_ip"], session["profile"])].append(session)
    signatures = {a.get("signature_id"): a.get("signature") for a in alerts}
    rows = []
    for decision in decisions:
        source = decision.get("source_ip")
        start = stamp(decision.get("start_time"))
        session = by_id.get(decision.get("event_id"))
        if session is None and start:
            candidates = [s for s in by_source[(source, decision.get("profile"))]
                          if 0 <= (stamp(s["first_action"]) - start).total_seconds() <= 1800]
            session = min(candidates, key=lambda s: s["first_action"]) if candidates else None
        identifier = decision.get("event_id") or hashlib.sha256(json.dumps(decision, sort_keys=True).encode()).hexdigest()
        rows.append({"id": identifier, "timestamp": decision.get("start_time"), "source_ip": source,
                     "action": decision.get("action"), "profile": decision.get("profile"),
                     "signature_id": decision.get("signature_id"), "severity": decision.get("severity"),
                     "rule_name": signatures.get(decision.get("signature_id")),
                     "reason": decision.get("reason"),
                     "dwell_seconds": session["dwell_seconds"] if session else None})
    rows.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    return rows


class DashboardState:
    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()

    def load(self):
        return json.loads(self.path.read_text(encoding="utf-8")) if self.path.is_file() else {}

    def save(self, data):
        atomic_text(self.path, json.dumps(data, ensure_ascii=False, indent=2))

    def visible(self, rows):
        with self.lock:
            cutoff = stamp(self.load().get("flushed_at"))
        return [r for r in rows if not cutoff or
                (stamp(r.get("timestamp") or r.get("start_time") or r.get("first_action")) or
                 datetime.min.replace(tzinfo=timezone.utc)) > cutoff]

    def notifications(self, username, rows, query):
        with self.lock:
            states = self.load().get("notifications", {}).get(username, {})
        items = [{**r, "read": states.get(r["id"]) == "read"} for r in rows if states.get(r["id"]) != "deleted"]
        unread = sum(not r["read"] for r in items)
        status = (query.get("status") or [""])[0]
        if status in {"read", "unread"}:
            items = [r for r in items if r["read"] == (status == "read")]
        if (query.get("order") or ["latest"])[0] == "oldest":
            items.reverse()
        try:
            limit = min(100, max(1, int((query.get("limit") or [25])[0])))
            offset = max(0, int((query.get("offset") or [0])[0]))
        except ValueError:
            raise ValueError("invalid_pagination")
        return {"items": items[offset:offset + limit], "total": len(items), "unread": unread,
                "offset": offset, "limit": limit}

    def mark(self, username, identifier, action, known):
        if identifier not in known or action not in {"read", "unread", "deleted"}:
            raise ValueError("invalid_notification")
        with self.lock:
            data = self.load()
            data.setdefault("notifications", {}).setdefault(username, {})[identifier] = action
            self.save(data)

    def flush(self):
        with self.lock:
            data = self.load()
            data["flushed_at"] = datetime.now(timezone.utc).isoformat()
            data["notifications"] = {}
            self.save(data)


def report_csv(report):
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["window", "section", "item", "count", "average_dwell_seconds"])
    for name in ("total_alerts", "total_decisions", "unique_source_ips", "high_severity_alerts", "honeypot_sessions"):
        writer.writerow([report["window"], "summary", name, report.get(name, 0), ""])
    for name in ("decision_protocols", "decision_severities", "destinations", "actions"):
        for key, count in report[name].items():
            if key != "blocked":
                writer.writerow([report["window"], name, key, count, ""])
    for item in report.get("honeypot_dwell", []):
        writer.writerow([report["window"], "honeypot_dwell", item["profile"], item["sessions"], item["average_seconds"]])
    return "\ufeff" + stream.getvalue()


class RuleStore:
    def __init__(self, path, backup_dir):
        self.path, self.backup_dir = path, backup_dir
        self.lock = threading.RLock()

    @staticmethod
    def check(rule):
        if not isinstance(rule, str) or "\n" in rule or "\r" in rule or len(rule) > 16384:
            raise ValueError("invalid_rule")
        matches = re.findall(r"\bsid\s*:\s*(\d+)\s*;", rule)
        if (not rule.startswith("alert ") or not rule.endswith(")") or len(matches) != 1
                or 'msg:"' not in rule or "classtype:" not in rule):
            raise ValueError("invalid_rule_syntax")
        return int(matches[0])

    def backup(self):
        token = "dashboard-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4) + ".rules"
        atomic_text(self.backup_dir / token, self.path.read_text(encoding="utf-8") if self.path.exists() else "")
        return token

    def backups(self):
        return [{"id": path.name, "size": path.stat().st_size} for path in
                sorted(self.backup_dir.glob("dashboard-*.rules"), reverse=True)]

    def change(self, payload):
        with self.lock:
            text = self.path.read_text(encoding="utf-8") if self.path.exists() else ""
            lines = text.splitlines()
            action = payload.get("action")
            if action == "restore":
                identifier = payload.get("backup", "")
                available = {entry["id"] for entry in self.backups()}
                if identifier not in available:
                    raise ValueError("backup_not_found")
                text = (self.backup_dir / identifier).read_text(encoding="utf-8")
            else:
                rule = payload.get("rule", "")
                if not isinstance(rule, str):
                    raise ValueError("invalid_rule")
                rule = rule.strip()
                sid = self.check(rule) if action in {"add", "edit"} else int(payload.get("sid", 0))
                existing = [(i, line) for i, line in enumerate(lines)
                            if re.search(r"\bsid\s*:\s*" + str(sid) + r"\s*;", line)]
                if action == "add":
                    if existing:
                        raise ValueError("duplicate_sid")
                    lines.append(rule)
                elif action in {"edit", "toggle"}:
                    if len(existing) != 1:
                        raise ValueError("rule_not_found")
                    i, old = existing[0]
                    if action == "edit":
                        if int(payload.get("sid", sid)) != sid:
                            raise ValueError("sid_must_not_change")
                        lines[i] = ("# DISABLED " if old.strip().startswith("# DISABLED ") else "") + rule
                    else:
                        if type(payload.get("enabled")) is not bool:
                            raise ValueError("invalid_rule_status")
                        lines[i] = (old.strip()[11:] if old.strip().startswith("# DISABLED ") else old.strip()) if payload["enabled"] else "# DISABLED " + (old.strip()[11:] if old.strip().startswith("# DISABLED ") else old.strip())
                else:
                    raise ValueError("invalid_rule_action")
                text = "\n".join(lines) + "\n"
            backup = self.backup()
            atomic_text(self.path, text)
            return {"ok": True, "backup": backup, "activation": "local"}


def threshold_config(path, payload=None):
    if not path or not path.is_file():
        raise ValueError("engine_config_missing")
    config = json.loads(path.read_text(encoding="utf-8"))
    if payload is not None:
        values = config["thresholds"].copy()
        for name in ("monitor", "redirect"):
            value = payload.get(name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError("invalid_threshold")
            values[name] = float(value)
        if not 0 <= values["monitor"] < values["redirect"] < values.get("temporary_block", 101):
            raise ValueError("thresholds_must_increase")
        config["thresholds"] = values
        atomic_text(path, json.dumps(config, indent=2) + "\n")
    return {key: config["thresholds"][key] for key in ("monitor", "redirect")}
