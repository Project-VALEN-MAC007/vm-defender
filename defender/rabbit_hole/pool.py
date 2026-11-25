"""Decoy pool for the Jev-driven Rabbit Hole (web).

Instead of fixed scenario graphs, the web decoy holds a pool of decoy items.
Each item may contain clue slots (``{{clue:<slot>}}``); for every session a
slot is filled with one item chosen from the slot's candidates. The choice
comes from the Jev plan pushed by the Defender (``planner.py``) or, when no
plan exists yet, from a deterministic per-session fallback. Once a slot has
been shown to an attacker it is frozen for that session so the decoy stays
consistent.

Hard limits the chooser cannot cross: max depth, max branches per item,
only items from the validated pool, only fake data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
import hashlib
import hmac
import json
from pathlib import Path
import re

from .render import Faker, placeholders, render

POOL_DIR = Path(__file__).resolve().parent / "pool"
KINDS = {"listing", "file", "api", "people_api", "form"}
KINDS_BY_PROTOCOL = {"web": KINDS, "shell": {"file", "dir"}}
CATEGORIES = {"recon": "สำรวจระบบ", "notes": "บันทึก/เอกสารภายใน", "backup": "ไฟล์สำรอง/โฟลเดอร์",
              "config": "ไฟล์ตั้งค่า", "credential": "รหัสผ่าน/คีย์", "api": "API", "admin": "หน้าแอดมิน",
              "data": "ข้อมูลคน/ลูกค้า"}
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
CLUE = re.compile(r"\{\{\s*clue:([a-z0-9_-]{1,32})\s*\}\}")
MAX_ITEMS = 120
MAX_BODY = 32768


class PoolError(ValueError):
    pass


@dataclass
class Slot:
    name: str
    categories: tuple
    kinds: tuple = ()
    under: bool = False
    count: int = 1


@dataclass
class Item:
    id: str
    kind: str
    category: str
    path_template: str
    description: str
    body: str = ""
    content_type: str = "text/plain; charset=utf-8"
    entry: bool = False
    lure: int = 1
    title: str = ""
    filler: list = field(default_factory=list)
    requires_header: dict = field(default_factory=dict)
    slots: dict = field(default_factory=dict)
    status: int = 200
    builtin: bool = False
    path: str = ""

    def public(self) -> dict:
        return {"id": self.id, "kind": self.kind, "category": self.category,
                "category_th": CATEGORIES.get(self.category, self.category), "path": self.path,
                "description": self.description, "entry": self.entry, "lure": self.lure,
                "builtin": self.builtin,
                "slots": [{"name": s.name, "categories": list(s.categories), "kinds": list(s.kinds),
                           "under": s.under, "count": s.count} for s in self.slots.values()]}


def _body(raw: dict) -> str:
    if "body_lines" in raw:
        lines = raw["body_lines"]
        if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines):
            raise PoolError("body_lines must be a list of strings")
        return "\n".join(lines) + ("\n" if lines else "")
    body = raw.get("body", "")
    if not isinstance(body, str):
        raise PoolError("body must be a string")
    return body


def parse_item(raw: dict, builtin: bool = False, protocol: str = "web") -> Item:
    if not isinstance(raw, dict):
        raise PoolError("item must be an object")
    iid = raw.get("id")
    if not isinstance(iid, str) or not ID_PATTERN.match(iid):
        raise PoolError(f"invalid item id {iid!r}")
    kind = raw.get("kind")
    if kind not in KINDS_BY_PROTOCOL[protocol]:
        raise PoolError(f"{iid}: unsupported kind {kind!r}")
    category = raw.get("category")
    if category not in CATEGORIES:
        raise PoolError(f"{iid}: unknown category {category!r}")
    path = raw.get("path")
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 300:
        raise PoolError(f"{iid}: path must start with /")
    if kind == "listing" and not path.endswith("/"):
        raise PoolError(f"{iid}: a listing path must end with /")
    if protocol == "shell" and (path.endswith("/") or "//" in path):
        raise PoolError(f"{iid}: shell paths must not end with /")
    description = raw.get("description")
    if not isinstance(description, str) or not 3 <= len(description) <= 300:
        raise PoolError(f"{iid}: description (3-300 chars) is required: Jev chooses by it")
    body = _body(raw)
    if len(body) > MAX_BODY:
        raise PoolError(f"{iid}: body larger than {MAX_BODY} bytes")
    lure = raw.get("lure", 1)
    if isinstance(lure, bool) or not isinstance(lure, int) or not 1 <= lure <= 3:
        raise PoolError(f"{iid}: lure must be 1-3")
    slots = {}
    for name, spec in (raw.get("slots") or {}).items():
        if not re.match(r"^[a-z0-9_-]{1,32}$", str(name)) or not isinstance(spec, dict):
            raise PoolError(f"{iid}: invalid slot {name!r}")
        cats = spec.get("categories") or []
        if not cats or any(c not in CATEGORIES for c in cats):
            raise PoolError(f"{iid}.{name}: categories must be from {sorted(CATEGORIES)}")
        kinds = spec.get("kinds") or []
        if any(k not in KINDS_BY_PROTOCOL[protocol] for k in kinds):
            raise PoolError(f"{iid}.{name}: unknown kind in kinds")
        count = spec.get("count", 1)
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 5:
            raise PoolError(f"{iid}.{name}: count must be 1-5")
        under = spec.get("under") is True
        if under and kind != "listing":
            raise PoolError(f"{iid}.{name}: only a listing can hold items under its path")
        slots[name] = Slot(name, tuple(cats), tuple(kinds), under, count)
    if kind == "dir" and (slots or body):
        raise PoolError(f"{iid}: a shell folder has no body or clue slots")
    used = set(CLUE.findall(body))
    missing = used - set(slots)
    if missing:
        raise PoolError(f"{iid}: body uses undefined slot(s) {sorted(missing)}")
    if kind == "listing":
        if any(not s.under for s in slots.values()):
            raise PoolError(f"{iid}: listing slots must set under=true")
    elif kind != "form":  # a login form's slot is where the POST redirects, not shown in the body
        unused = set(slots) - used
        if unused:
            raise PoolError(f"{iid}: slot(s) {sorted(unused)} never appear in the body")
    default_type = {"api": "application/json", "people_api": "application/json",
                    "listing": "text/html; charset=utf-8", "form": "text/html; charset=utf-8"}.get(
        kind, "text/plain; charset=utf-8")
    return Item(id=iid, kind=kind, category=category, path_template=path, description=description,
                body=body, content_type=str(raw.get("content_type") or default_type),
                entry=raw.get("entry") is True, lure=lure, title=str(raw.get("title") or ""),
                filler=[str(x) for x in raw.get("filler") or []],
                requires_header={str(k): str(v) for k, v in (raw.get("requires_header") or {}).items()},
                slots=slots, status=int(raw.get("status", 200)), builtin=builtin)


class Pool:
    def __init__(self, items: dict):
        self.items = items
        self.by_path = {item.path: item for item in items.values()}

    def candidates(self, item: Item, slot: Slot) -> list:
        result = []
        for other in self.items.values():
            if other.id == item.id or other.category not in slot.categories:
                continue
            if slot.kinds and other.kind not in slot.kinds:
                continue
            if slot.under:
                if not other.path.startswith(item.path) or other.path == item.path:
                    continue
                rest = other.path[len(item.path):].rstrip("/")
                if "/" in rest:  # direct children only
                    continue
            result.append(other)
        return result

    def problems(self, limits: dict, profile: dict) -> list:
        issues = []
        max_branches = int(limits.get("max_branches", 2))
        if not any(item.entry for item in self.items.values()):
            issues.append("pool has no entry item")
        for item in self.items.values():
            branches = sum(slot.count for slot in item.slots.values())
            if branches > max_branches:
                issues.append(f"{item.id}: {branches} clue branches > max_branches {max_branches}")
            for slot in item.slots.values():
                found = self.candidates(item, slot)
                if len(found) < slot.count:
                    issues.append(f"{item.id}.{slot.name}: only {len(found)} candidate(s) for {slot.count} place(s)")
        issues += self.check_templates(profile)
        return issues

    def check_templates(self, profile: dict) -> list:
        faker = Faker(b"validation", "validation", profile, date(2026, 1, 1))
        issues = []
        for item in self.items.values():
            texts = [item.body, item.path_template, item.title] + list(item.requires_header.values()) + item.filler
            for text in texts:
                for expr in placeholders(text):
                    if expr.startswith(("ctx.", "clue:")):
                        continue
                    try:
                        render("{{" + expr + "}}", faker, {})
                    except (KeyError, ValueError, IndexError) as exc:
                        issues.append(f"{item.id}: placeholder {{{{{expr}}}}} {exc}")
        return issues


def _load_file(path: Path, builtin: bool, protocol: str) -> list:
    """Items of ``protocol`` in one file. A file is web unless it says
    ``{"protocol": "shell", "items": [...]}`` (or an item has ``"protocol"``)."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PoolError(f"cannot read pool file {Path(path).name}: {exc}") from exc
    file_protocol = raw.get("protocol", "web") if isinstance(raw, dict) else "web"
    if isinstance(raw, dict) and "items" in raw:
        raw = raw["items"]
    if not isinstance(raw, list):
        raw = [raw]
    result = []
    for entry in raw:
        item_protocol = entry.get("protocol", file_protocol) if isinstance(entry, dict) else file_protocol
        if item_protocol not in KINDS_BY_PROTOCOL:
            raise PoolError(f"{Path(path).name}: unknown protocol {item_protocol!r}")
        if item_protocol == protocol:
            result.append(parse_item({k: v for k, v in entry.items() if k != "protocol"}, builtin, protocol))
    return result


def load_pool(custom_dirs=(), faker: Faker | None = None, errors: list | None = None,
              protocol: str = "web") -> Pool:
    items: dict = {}
    builtin_file = POOL_DIR / f"{protocol}.json"
    for item in _load_file(builtin_file, True, protocol) if builtin_file.is_file() else []:
        items[item.id] = item
    for directory in [Path(d) for d in custom_dirs]:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.json")):
            try:
                loaded = _load_file(path, False, protocol)
            except PoolError as exc:
                if errors is not None:
                    errors.append(str(exc))
                continue
            for item in loaded:
                if item.id in items:
                    if errors is not None:
                        errors.append(f"{path.name}: id {item.id} already exists")
                    continue
                items[item.id] = item
    if len(items) > MAX_ITEMS:
        raise PoolError(f"pool larger than {MAX_ITEMS} items")
    if faker is not None:
        seen = {}
        for item in items.values():
            item.path = render(item.path_template, faker, {})
            if item.path in seen:
                raise PoolError(f"path {item.path} used by {seen[item.path]} and {item.id}")
            seen[item.path] = item.id
    else:
        for item in items.values():
            item.path = item.path_template
    return Pool(items)


def slot_key(item_id: str, slot: str) -> str:
    return f"{item_id}.{slot}"


def fallback_order(secret: bytes, session: str, key: str, candidates: list) -> list:
    """Deterministic per-session order: more tempting items first, with a keyed
    shuffle so different sessions do not all see the same path."""
    def score(item):
        mac = hmac.new(secret, f"{session}|{key}|{item.id}".encode("utf-8"), hashlib.sha256).digest()
        return item.lure + mac[0] / 255 * 1.5
    return sorted(candidates, key=score, reverse=True)


# ---------------------------------------------------------------------------
# Rendering (shared by the web decoy and the dashboard preview)
# ---------------------------------------------------------------------------

def fill_clues(item: Item, choices: dict) -> str:
    """Put the chosen paths into ``{{clue:x}}``. A line whose clue has no choice
    (depth limit reached) is dropped, except in JSON where it becomes ""."""
    out = []
    for line in item.body.split("\n"):
        names = CLUE.findall(line)
        if not names:
            out.append(line)
            continue
        if any(not choices.get(name) for name in names):
            if item.kind != "api":
                continue
        out.append(CLUE.sub(lambda m: ", ".join(c.path for c in choices.get(m.group(1)) or []), line))
    return "\n".join(out)


def render_item(item: Item, faker: Faker, choices: dict, deployment: Faker, context: dict | None = None,
                item_id: int | None = None) -> str | None:
    if item.kind == "listing":
        return _listing(item, faker, choices, deployment)
    if item.kind == "people_api":
        count = int(item.body or 10)
        people = faker.people(count)
        if item_id is None:
            return json.dumps({"items": [{k: p[k] for k in ("id", "name", "email", "role")} for p in people],
                              "total": count}, indent=2)
        match = [p for p in people if p["id"] == item_id]
        return json.dumps(match[0], indent=2) if match else None
    return render(fill_clues(item, choices), faker, {}, context or {})


def _listing(item: Item, faker: Faker, choices: dict, deployment: Faker) -> str:
    from datetime import datetime
    from html import escape
    entries = []
    for children in choices.values():
        for child in children:
            name = child.path[len(item.path):]
            size = "-" if child.kind == "listing" else str(len(render_item(child, faker, {}, deployment) or ""))
            entries.append((name, size))
    for name in item.filler:
        rendered = render(name, deployment, {})
        entries.append((rendered, str(faker.number("size:" + rendered, 40000, 9000000))))
    stamp = faker.day(-faker.number("listing:" + item.id, 1, 20))
    lines = ['<a href="../">../</a>']
    for name, size in sorted(entries):
        when = datetime.strptime(stamp, "%Y-%m-%d").strftime("%d-%b-%Y") + " 02:" + \
            str(faker.number("min:" + name, 10, 59))
        lines.append(f'<a href="{escape(name, quote=True)}">{escape(name)}</a>' + " " * max(1, 51 - len(name)) +
                     f"{when}{size:>20}")
    title = escape(item.path)
    return (f"<html>\r\n<head><title>Index of {title}</title></head>\r\n<body>\r\n"
            f"<h1>Index of {title}</h1><hr><pre>" + "\r\n".join(lines) + "\r\n</pre><hr></body>\r\n</html>\r\n")


class PlanStore:
    """Per-IP clue plans written by the Defender's Jev planner. Re-read when the
    file changes; a broken file is ignored (the fallback keeps working)."""

    def __init__(self, path: Path | None):
        self.path = Path(path) if path else None
        self._stamp = None
        self.data: dict = {}

    def _refresh(self) -> None:
        if not self.path:
            return
        try:
            stat = self.path.stat()
        except OSError:
            self.data, self._stamp = {}, None
            return
        stamp = (stat.st_mtime_ns, stat.st_size)
        if stamp == self._stamp:
            return
        self._stamp = stamp
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            ips = raw.get("ips") if isinstance(raw, dict) else None
            self.data = ips if isinstance(ips, dict) else {}
        except (OSError, ValueError):
            self.data = {}

    def for_ip(self, ip: str) -> dict:
        self._refresh()
        plan = self.data.get(ip)
        choices = plan.get("choices") if isinstance(plan, dict) else None
        return choices if isinstance(choices, dict) else {}
