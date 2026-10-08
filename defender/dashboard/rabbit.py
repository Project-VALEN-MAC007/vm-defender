"""Dashboard side of Rabbit Hole: read logs, build reports, manage settings."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import threading

from ..rabbit_hole import analytics as rabbit_analytics
from ..rabbit_hole import config as rabbit_config
from ..rabbit_hole import shell as rabbit_shell
from ..rabbit_hole import custom
from ..rabbit_hole.render import Faker, render
from ..rabbit_hole.scenario import parse as parse_scenario, resolve_paths
from ..rabbit_hole.web import WebEngine

WINDOWS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30), "all": None}


def rabbit_transform(event: dict, path) -> dict | None:
    if event.get("event") != "rabbit_hole.web" or not event.get("session_id") or not event.get("timestamp"):
        return None
    return {**event, "source_file": str(path)}


class RabbitHoleService:
    def __init__(self, config_path, root):
        self.config_path = config_path
        self.root = root
        self.lock = threading.Lock()
        self._cached = None
        self._mtime = None

    @property
    def available(self) -> bool:
        return self.config_path is not None

    def config(self) -> rabbit_config.RabbitConfig:
        if self.config_path is None:
            raise ValueError("rabbit_hole_not_configured")
        with self.lock:
            mtime = self.config_path.stat().st_mtime if self.config_path.is_file() else None
            if self._cached is None or mtime != self._mtime:
                self._cached = rabbit_config.load(self.config_path)
                self._mtime = mtime
            return self._cached

    def events(self, web_rows: list, honeypot_rows: list) -> list:
        """Web decoy events plus Cowrie commands converted to Rabbit Hole events."""
        if self.config_path is None:
            return []
        config = self.config()
        cowrie = [row for row in honeypot_rows if str(row.get("eventid", "")).startswith("cowrie.")]
        try:
            shell_events = rabbit_shell.events_from_cowrie(cowrie, config)
        except ValueError:
            shell_events = []
        return list(web_rows) + shell_events

    def report(self, events: list, window: str, static_sessions: list, now=None) -> dict:
        if window not in WINDOWS:
            raise ValueError("invalid window")
        now = now or datetime.now(timezone.utc)
        config = self.config()
        items = rabbit_analytics.windows(events, config.limits["idle_timeout_seconds"], now)
        span = WINDOWS[window]
        if span is not None:
            cutoff = (now - span).isoformat()
            items = [w for w in items if w["start"] >= cutoff]
            static_sessions = [s for s in static_sessions if str(s.get("first_action")) >= cutoff]
        summary = rabbit_analytics.summarize(items, static_sessions)
        light = [{k: v for k, v in w.items() if k != "trail"} for w in items[:200]]
        return {"window": window, "enabled": config.enabled, "summary": summary,
                "windows": light, "total_windows": len(items),
                "idle_timeout_seconds": config.limits["idle_timeout_seconds"],
                "scenarios": self.catalog(), "settings": config.public(),
                "problems": config.problems()}

    def web_sessions(self, web_rows: list) -> list:
        """Rabbit Hole web windows in the session format used for Honeypot dwell time."""
        idle = self.config().limits["idle_timeout_seconds"]
        return [{"session_id": w["id"], "source_ip": w["source_ip"], "profile": "rabbithole",
                 "first_action": w["start"], "last_action": w["end"], "timestamp": w["start"],
                 "actions": w["events"]}
                for w in rabbit_analytics.windows(web_rows, idle) if w["family"] == "web"]

    def window_detail(self, events: list, identifier: str) -> dict:
        config = self.config()
        for item in rabbit_analytics.windows(events, config.limits["idle_timeout_seconds"]):
            if item["id"] == identifier:
                return item
        raise ValueError("window_not_found")

    def catalog(self) -> list:
        config = self.config()
        faker = config.deployment_faker()
        selected = set(config.data["scenarios"]["web"]) | {config.data["scenarios"].get("shell")}
        result = []
        for scenario in config.all_scenarios().values():
            try:
                resolve_paths(scenario, faker)
            except (KeyError, ValueError):
                continue
            result.append({
                "id": scenario.id, "title": scenario.title, "description": scenario.description,
                "protocol": scenario.protocol, "selected": scenario.id in selected,
                "builtin": scenario.builtin, "max_depth": scenario.max_depth(),
                "nodes": [{"id": n.id, "path": n.path, "kind": n.kind, "depth": n.depth,
                           "next": n.next, "entry": n.id in scenario.entry}
                          for n in sorted(scenario.nodes.values(), key=lambda n: (n.depth, n.path))]})
        result.sort(key=lambda s: (s["builtin"], s["protocol"], s["title"]))
        return result

    def _render(self, config, scenario) -> list:
        resolve_paths(scenario, config.deployment_faker())
        paths = scenario.node_paths()
        resources = []
        if scenario.protocol == "shell":
            faker = Faker(config.secret(), "shell", config.organization, config.anchor_date())
            for node in sorted(scenario.nodes.values(), key=lambda n: (n.depth, n.path)):
                content = "" if node.kind == "dir" else render(node.body, faker, paths)
                resources.append({"id": node.id, "path": node.path, "kind": node.kind, "depth": node.depth,
                                  "requires": [], "content": content[:4000]})
            return resources
        engine = WebEngine(config, clock=lambda: 0.0)
        faker = Faker(config.secret(), "web:preview", config.organization)
        for node in sorted(scenario.nodes.values(), key=lambda n: (n.depth, n.path)):
            content = engine._content(scenario, node, faker, paths, {}, None) or ""
            resources.append({"id": node.id, "path": node.path, "kind": node.kind, "depth": node.depth,
                              "requires": sorted(node.requires_header), "content": content[:4000]})
        return resources

    def preview(self, scenario_id: str) -> dict:
        """What an attacker would see in one sample session, for the admin to review."""
        config = self.config()
        catalog = config.all_scenarios()
        if scenario_id not in catalog:
            raise ValueError("scenario_not_found")
        scenario = catalog[scenario_id]
        return {"scenario": scenario_id, "protocol": scenario.protocol,
                "resources": self._render(config, scenario),
                "note": "ตัวอย่างจาก Session จำลอง ค่าลับจะต่างกันในแต่ละ Session จริง"}

    def preview_draft(self, raw: dict) -> dict:
        config = self.config()
        report = custom.check(raw, config)
        if report["errors"]:
            return {"report": report, "resources": []}
        scenario = parse_scenario(custom._clean(raw))
        return {"report": report, "protocol": scenario.protocol, "resources": self._render(config, scenario),
                "note": "ตัวอย่างจาก Session จำลอง ค่าลับจะต่างกันในแต่ละ Session จริง"}

    def check_draft(self, raw: dict) -> dict:
        return custom.check(raw, self.config())

    def definition(self, scenario_id: str) -> dict:
        return custom.definition(self.config(), scenario_id)

    def save_scenario(self, raw: dict) -> dict:
        return custom.save(self.config(), raw)

    def delete_scenario(self, scenario_id: str) -> dict:
        return custom.delete(self.config(), scenario_id)

    def save(self, payload: dict) -> dict:
        allowed = {k: payload[k] for k in ("enabled", "organization", "scenarios", "limits") if k in payload}
        updated = self.config().save(allowed)
        with self.lock:
            self._cached, self._mtime = None, None
        return {"ok": True, "settings": updated.public()}

    def bundle(self) -> bytes:
        return rabbit_shell.export_bundle(self.config())


def log_rows(events: list) -> list:
    rows = []
    for event in events:
        if event.get("action") == "session_closed":
            continue
        where = event.get("path") or event.get("command") or ""
        node = event.get("node_id")
        detail = f"{event.get('method', '')} {where}".strip()
        if event.get("status") is not None:
            detail += f" → {event['status']}"
        if node:
            detail += f" · {node} (ชั้น {event.get('depth')})"
        if event.get("followed_clue"):
            detail += " · ตามเบาะแส"
        rows.append({"type": "rabbit_hole", "time": event.get("timestamp"), "source": event.get("source_ip"),
                     "protocol": str(event.get("protocol") or "").upper(), "severity": None,
                     "summary": detail, "result": event.get("action")})
    return rows
