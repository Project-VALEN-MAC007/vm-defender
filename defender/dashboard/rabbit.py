"""Dashboard side of Rabbit Hole: read logs, build reports, manage settings."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import json
import os
import re
import threading

from ..rabbit_hole import analytics as rabbit_analytics
from ..rabbit_hole import config as rabbit_config
from ..rabbit_hole import shell as rabbit_shell
from ..rabbit_hole import custom
from ..rabbit_hole import jev
from ..rabbit_hole import pool as rabbit_pool
from ..rabbit_hole.render import Faker, render
from ..rabbit_hole.scenario import parse as parse_scenario, resolve_paths
from ..rabbit_hole.web import WebEngine

WINDOWS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30), "all": None}


def rabbit_transform(event: dict, path) -> dict | None:
    # rabbit_hole.shell comes from the trap-rabbit Cowrie plugin (Jev mode).
    if event.get("event") not in {"rabbit_hole.web", "rabbit_hole.shell"} or not event.get("session_id") \
            or not event.get("timestamp"):
        return None
    return {**event, "source_file": str(path)}


class RabbitHoleService:
    def __init__(self, config_path, root):
        self.config_path = config_path
        self.root = root
        self.lock = threading.Lock()
        self._cached = None
        self._mtime = None
        self._profiler = None
        self._profiler_settings = None

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
                "problems": config.problems(), "ai": self.ai_status(),
                "strategy": config.strategy, "pool": self.pool_catalog(), "plan": self.plan_status()}

    def web_sessions(self, web_rows: list) -> list:
        """Rabbit Hole web windows in the session format used for Honeypot dwell time."""
        idle = self.config().limits["idle_timeout_seconds"]
        return [{"session_id": w["id"], "source_ip": w["source_ip"], "profile": "rabbithole",
                 "protocol": w.get("protocol") or "http",
                 "first_action": w["start"], "last_action": w["end"], "timestamp": w["start"],
                 "actions": w["events"]}
                for w in rabbit_analytics.windows(web_rows, idle) if w["family"] == "web"]

    def window_detail(self, events: list, identifier: str) -> dict:
        config = self.config()
        for item in rabbit_analytics.windows(events, config.limits["idle_timeout_seconds"]):
            if item["id"] == identifier:
                return item
        raise ValueError("window_not_found")

    def profiler(self) -> jev.Profiler:
        config = self.config()
        settings = config.ai
        with self.lock:
            if self._profiler is None or settings != self._profiler_settings:
                client = jev.JevClient(dict(settings), key_file=config.ai_key_path())
                self._profiler = jev.Profiler(dict(settings), client)
                self._profiler_settings = dict(settings)
            return self._profiler

    def ai_status(self) -> dict:
        client = self.profiler().client
        return {"enabled": bool(self.config().ai["enabled"]), "key_set": client.has_key,
                "key_source": client.key_source(), "key_hint": jev.key_hint(client.key()),
                "key_env": client.key_env}

    def save_ai(self, payload: dict) -> dict:
        """Master Admin: switch Jev on/off and set or clear the API key.
        The key is written to a separate owner-only file and never echoed back."""
        config = self.config()
        key = payload.get("api_key")
        if payload.get("clear_key"):
            jev.write_key_file(config.ai_key_path(), None)
        elif isinstance(key, str) and key.strip():
            jev.write_key_file(config.ai_key_path(), key)
        elif key not in (None, ""):
            raise ValueError("invalid_api_key_format")
        if "enabled" in payload:
            config.save_ai(payload["enabled"])
        with self.lock:
            self._cached, self._mtime, self._profiler = None, None, None
        return {"ok": True, "ai": self.ai_status()}

    def test_ai(self) -> dict:
        return self.profiler().test()

    def ai_profile(self, events: list, identifier: str) -> dict:
        """Jev assessment of one tracking window; never raises for API problems."""
        window = self.window_detail(events, identifier)
        return self.profiler().profile(window, events)

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
        allowed = {k: payload[k] for k in ("enabled", "strategy", "organization", "scenarios", "limits")
                   if k in payload}
        updated = self.config().save(allowed)
        with self.lock:
            self._cached, self._mtime = None, None
        return {"ok": True, "settings": updated.public()}

    # ---------- Jev decoy pool ----------
    def pool_catalog(self) -> dict:
        config = self.config()
        errors: list = []
        try:
            pool = config.pool(errors)
        except (rabbit_pool.PoolError, KeyError, ValueError) as exc:
            return {"items": [], "errors": [str(exc)], "categories": rabbit_pool.CATEGORIES}
        def view(item):
            data = item.public()
            if not item.builtin:  # the admin's own items come with their definition for editing
                try:
                    raw = json.loads((config.pool_dir / f"{item.id}.json").read_text(encoding="utf-8"))
                    data["raw"] = raw[0] if isinstance(raw, list) and raw else raw
                except (OSError, ValueError):
                    data["raw"] = None
            return data
        try:
            shell = [item.public() for item in sorted(config.pool(protocol="shell").items.values(),
                                                      key=lambda i: (not i.entry, i.category, i.path))]
        except (rabbit_pool.PoolError, KeyError, ValueError) as exc:
            shell, errors = [], errors + [f"shell pool: {exc}"]
        return {"items": [view(item) for item in sorted(pool.items.values(),
                                                       key=lambda i: (not i.entry, i.category, i.path))],
                "shell_items": shell,
                "errors": errors, "categories": rabbit_pool.CATEGORIES}

    def plan_status(self) -> dict:
        """What the Defender's Jev planner last wrote (it runs as its own service)."""
        path = self.config().plan_path
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"exists": False}
        except (OSError, ValueError):
            return {"exists": True, "error": "unreadable"}
        ips = raw.get("ips") if isinstance(raw.get("ips"), dict) else {}
        recent = sorted(ips.items(), key=lambda kv: str(kv[1].get("updated")), reverse=True)[:10]
        goals = Counter(str((plan.get("goal") or {}).get("label") or "other") for plan in ips.values())
        return {"exists": True, "generated": raw.get("generated"), "attackers": len(ips), "goals": dict(goals),
                "recent": [{"source_ip": ip, "updated": plan.get("updated"), "goal": plan.get("goal"),
                            "choices": len(plan.get("choices") or {})} for ip, plan in recent]}

    def pool_preview(self, item_id: str) -> dict:
        config = self.config()
        pool = config.pool()
        if item_id not in pool.items:
            raise ValueError("pool_item_not_found")
        item = pool.items[item_id]
        faker = Faker(config.secret(), "web:preview", config.organization)
        secret = config.secret()
        choices = {}
        for slot in item.slots.values():
            ordered = rabbit_pool.fallback_order(secret, "preview", rabbit_pool.slot_key(item.id, slot.name),
                                                 pool.candidates(item, slot))
            choices[slot.name] = ordered[:slot.count]
        content = rabbit_pool.render_item(item, faker, choices, config.deployment_faker()) or ""
        return {"item": item.public(), "content": content[:6000],
                "candidates": {slot.name: [{"id": c.id, "path": c.path, "category": c.category}
                                           for c in pool.candidates(item, slot)] for slot in item.slots.values()},
                "note": "ตัวอย่างใช้ตัวเลือกสำรอง (fallback) เมื่อมีแผนจาก Jev ระบบจะใช้ชิ้นที่ Jev เลือกแทน"}

    def save_pool_item(self, raw: dict) -> dict:
        """Add or replace one admin item. Built-in items cannot be overwritten."""
        config = self.config()
        item = rabbit_pool.parse_item(raw)
        pool = config.pool()
        if item.id in pool.items and pool.items[item.id].builtin:
            raise ValueError("builtin_item_cannot_be_changed")
        target = config.pool_dir / f"{item.id}.json"
        config.pool_dir.mkdir(parents=True, exist_ok=True)
        previous = target.read_text(encoding="utf-8") if target.is_file() else None
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, target)
        try:
            problems = config.pool().problems(config.limits, config.organization)
        except (rabbit_pool.PoolError, KeyError, ValueError) as exc:
            problems = [str(exc)]
        if problems:
            if previous is None:
                target.unlink()
            else:
                target.write_text(previous, encoding="utf-8")
            raise ValueError("pool_check_failed: " + "; ".join(problems[:5]))
        if previous is not None:
            backups = config.pool_dir / ".backups"
            backups.mkdir(exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            (backups / f"{item.id}.{stamp}.json").write_text(previous, encoding="utf-8")
        return {"ok": True, "pool": self.pool_catalog()}

    def delete_pool_item(self, item_id: str) -> dict:
        config = self.config()
        if not isinstance(item_id, str) or not re.match(r"^[a-z0-9][a-z0-9_-]{0,63}$", item_id):
            raise ValueError("invalid_item_id")
        target = config.pool_dir / f"{item_id}.json"
        if not target.is_file():
            raise ValueError("custom_item_not_found")
        previous = target.read_text(encoding="utf-8")
        target.unlink()
        try:
            problems = config.pool().problems(config.limits, config.organization)
        except (rabbit_pool.PoolError, KeyError, ValueError) as exc:
            problems = [str(exc)]
        if problems:
            target.write_text(previous, encoding="utf-8")
            raise ValueError("pool_check_failed: " + "; ".join(problems[:5]))
        backups = config.pool_dir / ".backups"
        backups.mkdir(exist_ok=True)
        (backups / f"{item_id}.deleted.json").write_text(previous, encoding="utf-8")
        return {"ok": True, "pool": self.pool_catalog()}

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
