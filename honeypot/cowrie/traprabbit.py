"""TRAP Rabbit Hole plugin for Cowrie: Jev-chosen clues for SSH and Telnet.

Cowrie serves one fixed filesystem to every session. This plugin makes the
decoy files of the Rabbit Hole shell pool per-attacker: when an attacker reads a
decoy (cat, less, head, ...), each ``{{clue:<slot>}}`` in it is filled with the
item the Defender's Jev planner chose for that source IP, or with a
deterministic fallback when there is no plan yet. A clue, once shown, stays the
same for the session. Reads and clue choices are written as Rabbit Hole events
(``rabbit_hole.shell``) next to Cowrie's own log so the Defender syncs them.

Install (see honeypot/docker/README.md):
  * mount this file as  /cowrie/cowrie-git/src/cowrie/output/traprabbit.py  (read-only)
  * cowrie.cfg:  [output_traprabbit]  enabled = true
Cowrie imports ``cowrie.output.traprabbit`` at start; importing it installs the
hooks. If anything is missing (no bundle, unknown Cowrie internals) Cowrie keeps
serving the static decoy files installed by trap-cowrie-sync, unchanged.

Standard library + Cowrie only. Never reads the deployment secret, never opens
network connections (the Honeypot has no outbound route by design).
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import posixpath
import re
import sys
import time
import weakref

BUNDLE_PATH = os.environ.get("TRAP_SHELL_POOL", "/cowrie/trapfs/trap-shell-pool.json")
PLAN_PATH = os.environ.get("TRAP_PLAN", "/cowrie/trapfs/rabbit-hole-plan.json")
LOG_PATH = os.environ.get("TRAP_SHELL_LOG", "/cowrie/cowrie-git/var/log/cowrie/trap-rabbit-shell.jsonl")
CLUE = re.compile(r"\{\{\s*clue:([a-z0-9_-]{1,32})\s*\}\}")
CONTEXT = "_trap_rabbit"
PROTOCOL_REF = "_trap_rabbit_protocol"


def _note(message: str) -> None:
    print(f"[traprabbit] {message}", file=sys.stderr, flush=True)


class _JsonFile:
    """JSON file re-read only when it changes; a broken file keeps the last good value."""

    def __init__(self, path: str):
        self.path, self.stamp, self.value = path, None, None

    def get(self):
        try:
            stat = os.stat(self.path)
        except OSError:
            self.stamp, self.value = None, None
            return None
        stamp = (stat.st_mtime_ns, stat.st_size)
        if stamp != self.stamp:
            try:
                with open(self.path, encoding="utf-8") as stream:
                    self.value = json.load(stream)
                self.stamp = stamp
            except (OSError, ValueError):
                pass
        return self.value


class Engine:
    def __init__(self, bundle_path=BUNDLE_PATH, plan_path=PLAN_PATH, log_path=LOG_PATH, clock=time.time):
        self.bundle_file = _JsonFile(bundle_path)
        self.plan_file = _JsonFile(plan_path)
        self.log_path = log_path
        self.clock = clock

    # ---------- data ----------
    def bundle(self) -> dict | None:
        value = self.bundle_file.get()
        return value if isinstance(value, dict) and isinstance(value.get("items"), dict) else None

    def item_at(self, path: str):
        bundle = self.bundle()
        if not bundle:
            return None, None
        for item_id, item in bundle["items"].items():
            if item.get("path") == path:
                return item_id, item
        return None, None

    def plan_for(self, ip: str) -> dict:
        value = self.plan_file.get()
        plans = value.get("ips") if isinstance(value, dict) else None
        plan = plans.get(ip) if isinstance(plans, dict) else None
        choices = plan.get("choices") if isinstance(plan, dict) else None
        return choices if isinstance(choices, dict) else {}

    @staticmethod
    def new_context(ip: str, session: str, protocol: str) -> dict:
        return {"ip": ip, "session": session, "protocol": protocol, "choices": {}, "revealed": {},
                "depths": {}, "meta": {}, "accessed": []}

    # ---------- choosing ----------
    def _fallback(self, salt: str, session: str, key: str, candidates: list, items: dict) -> list:
        def score(item_id):
            mac = hmac.new(salt.encode("utf-8"), f"{session}|{key}|{item_id}".encode("utf-8"), hashlib.sha256).digest()
            return int(items[item_id].get("lure", 1)) + mac[0] / 255 * 1.5
        return sorted(candidates, key=score, reverse=True)

    def choose(self, ctx: dict, item_id: str, item: dict, depth: int, bundle: dict) -> dict:
        if depth >= int(bundle.get("max_depth", 5)) or not item.get("slots"):
            return {}
        items = bundle["items"]
        plan = self.plan_for(ctx["ip"])
        result, used = {}, set()
        for name, slot in item["slots"].items():
            key = f"{item_id}.{name}"
            frozen = ctx["choices"].get(key)
            if frozen is None:
                count = max(1, int(slot.get("count", 1)))
                candidates = [c for c in slot.get("candidates") or [] if c in items and c not in used]
                fresh = [c for c in candidates if c not in ctx["revealed"] and c not in ctx["accessed"]]
                if len(fresh) >= count:
                    candidates = fresh
                planned = plan.get(key) if isinstance(plan.get(key), dict) else {}
                chosen = [c for c in planned.get("items") or [] if c in candidates][:count]
                by = "jev" if chosen else "fallback"
                confidence = planned.get("confidence") if chosen and isinstance(planned.get("confidence"), (int, float)) else None
                rest = [c for c in candidates if c not in chosen]
                chosen += self._fallback(bundle.get("salt", ""), ctx["session"], key, rest, items)[:count - len(chosen)]
                frozen = ctx["choices"][key] = {"items": chosen, "by": by, "confidence": confidence}
            used.update(frozen["items"])
            if frozen["items"]:
                result[name] = frozen["items"]
        return result

    @staticmethod
    def fill(template: str, choices: dict, items: dict) -> str:
        lines = []
        for line in template.split("\n"):
            names = CLUE.findall(line)
            if names and any(not choices.get(n) for n in names):
                continue  # clue past the depth limit: drop the line
            lines.append(CLUE.sub(lambda m: ", ".join(items[i]["path"] for i in choices.get(m.group(1)) or []), line))
        return "\n".join(lines)

    # ---------- access ----------
    def access(self, ctx: dict, path: str, action: str) -> bytes | None:
        """Decoy content for this session, or None to let Cowrie serve its own file."""
        bundle = self.bundle()
        if not bundle:
            return None
        item_id, item = self.item_at(path)
        if item is None:
            return None
        if item_id not in ctx["accessed"] and len(ctx["accessed"]) >= int(bundle.get("max_resources", 40)):
            return None
        depth = ctx["depths"].get(item_id, 1)
        choices = self.choose(ctx, item_id, item, depth, bundle)
        event = {"timestamp": datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(),
                 "event": "rabbit_hole.shell", "profile": "cowrie", "protocol": ctx["protocol"],
                 "session_id": ctx["session"], "link": "cowrie_session", "source_ip": ctx["ip"],
                 "action": action, "path": path, "command": None, "scenario": "jev-pool",
                 "node_id": item_id, "resource_id": item_id, "kind": item.get("kind"),
                 "category": item.get("category"), "depth": depth, "clue_from": None, "followed_clue": False,
                 "limit_reached": False, "status": 200, "evidence": "content_served"}
        if item_id in ctx["revealed"]:
            meta = ctx["meta"].get(item_id) or {}
            event.update(clue_from=ctx["revealed"][item_id], followed_clue=True,
                         clue_by=meta.get("by"), clue_confidence=meta.get("confidence"))
        if choices:
            event["clue_choices"] = [{"slot": name, **ctx["choices"][f"{item_id}.{name}"]} for name in choices]
        first = item_id not in ctx["accessed"]
        if first:
            ctx["accessed"].append(item_id)
        for name, chosen in choices.items():
            meta = ctx["choices"][f"{item_id}.{name}"]
            for child in chosen:
                if child not in ctx["revealed"]:
                    ctx["revealed"][child] = item_id
                    ctx["depths"][child] = depth + 1
                    ctx["meta"][child] = {"by": meta["by"], "confidence": meta["confidence"]}
        if first or action == "read_file":
            self.log(event)
        if item.get("kind") == "dir":
            return None
        return self.fill(item.get("template") or "", choices, bundle["items"]).encode("utf-8")

    def log(self, event: dict) -> None:
        try:
            with open(self.log_path, "a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        except OSError:
            pass


ENGINE = Engine()


# ---------------------------------------------------------------------------
# Hooks into Cowrie
# ---------------------------------------------------------------------------

def _walk_session(protocol) -> tuple:
    """Cowrie's session id (``transportId``, the ``session`` field of cowrie.json)
    and whether the connection is Telnet, found by walking the transport chain."""
    queue, seen, telnet = [(protocol, 0)], set(), False
    while queue:
        obj, level = queue.pop(0)
        if obj is None or id(obj) in seen or level > 5:
            continue
        seen.add(id(obj))
        telnet = telnet or "telnet" in type(obj).__name__.lower()
        value = getattr(obj, "transportId", None)
        if isinstance(value, (str, bytes)) and value:
            return (value.decode() if isinstance(value, bytes) else value), telnet
        for name in ("pt", "transport", "terminal", "session", "conn", "factory"):
            try:
                queue.append((getattr(obj, name, None), level + 1))
            except Exception:  # some Twisted attributes raise on access
                continue
    return None, telnet


def _attach(protocol) -> None:
    fs = getattr(protocol, "fs", None)
    if fs is None:
        return
    ip = str(getattr(protocol, "realClientIP", None) or getattr(protocol, "clientIP", "") or "")
    session, telnet = _walk_session(protocol)
    session = session or f"{ip}-{getattr(protocol, 'sessionno', 'x')}"
    setattr(fs, CONTEXT, Engine.new_context(ip, session, "telnet" if telnet else "ssh"))
    setattr(fs, PROTOCOL_REF, weakref.ref(protocol))


def _absolute(fs, target) -> str | None:
    """Commands such as tail may pass a path relative to the shell's cwd."""
    if not isinstance(target, str) or not target:
        return None
    if not target.startswith("/"):
        ref = getattr(fs, PROTOCOL_REF, None)
        protocol = ref() if ref else None
        cwd = getattr(protocol, "cwd", None)
        if not isinstance(cwd, str):
            return None
        target = posixpath.join(cwd, target)
    return posixpath.normpath(target)


def install_patches(fs_cls=None, protocol_cls=None, engine: Engine | None = None) -> bool:
    engine = engine or ENGINE
    if fs_cls is None or protocol_cls is None:
        try:
            from cowrie.shell import fs as cowrie_fs
            from cowrie.shell import protocol as cowrie_protocol
        except Exception as exc:  # not running inside Cowrie
            _note(f"Cowrie modules not found, plugin inactive: {exc}")
            return False
        fs_cls = fs_cls or cowrie_fs.HoneyPotFilesystem
        protocol_cls = protocol_cls or cowrie_protocol.HoneyPotBaseProtocol
    if getattr(fs_cls, "_trap_rabbit_patched", False):
        return True

    original_contents = fs_cls.file_contents
    original_get_path = getattr(fs_cls, "get_path", None)
    original_connection = protocol_cls.connectionMade

    def file_contents(self, target, *args, **kwargs):
        ctx = getattr(self, CONTEXT, None)
        path = _absolute(self, target) if ctx is not None else None
        if path is not None:
            try:
                data = engine.access(ctx, path, "read_file")
            except Exception as exc:  # never break the attacker's shell
                _note(f"read hook failed: {exc}")
                data = None
            if data is not None:
                return data
        return original_contents(self, target, *args, **kwargs)

    def get_path(self, path, *args, **kwargs):
        result = original_get_path(self, path, *args, **kwargs)
        ctx = getattr(self, CONTEXT, None)
        absolute = _absolute(self, path) if ctx is not None else None
        if absolute is not None:
            try:
                engine.access(ctx, absolute, "list_directory")
            except Exception as exc:
                _note(f"list hook failed: {exc}")
        return result  # listings are never altered

    def connectionMade(self, *args, **kwargs):
        value = original_connection(self, *args, **kwargs)
        try:
            _attach(self)
        except Exception as exc:
            _note(f"session context failed: {exc}")
        return value

    fs_cls.file_contents = file_contents
    if original_get_path is not None:
        fs_cls.get_path = get_path
    protocol_cls.connectionMade = connectionMade
    fs_cls._trap_rabbit_patched = True
    _note("Rabbit Hole Jev hooks installed")
    return True


try:  # Cowrie loads output plugins as cowrie.output.<name> and needs an Output class.
    from cowrie.core import output as _cowrie_output
    _Base = _cowrie_output.Output
except Exception:
    _Base = object


class Output(_Base):  # type: ignore[misc, valid-type]
    """No-op output: the plugin is loaded for its hooks, not to forward events."""

    def start(self):
        pass

    def stop(self):
        pass

    def write(self, event):
        pass


if _Base is not object:
    install_patches()
