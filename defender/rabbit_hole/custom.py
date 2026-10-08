"""Scenarios designed by the user in the dashboard.

Built-in scenarios are read-only templates. A user copies one (or starts
empty), edits it in the dashboard and saves it into ``custom_scenario_dir``.
Every save is validated first and the previous version is kept in
``.backups/``.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets

from . import scenario as scenario_mod
from .config import RabbitConfig
from .render import placeholders

MAX_NODES = 40
MAX_BODY = 32768
MAX_TITLE = 120
MAX_DESCRIPTION = 600
PATH_PATTERN = re.compile(r"^/[A-Za-z0-9._~\-/{}:+@ ]{0,200}$")
CONTENT_TYPES = {"text/plain; charset=utf-8", "text/html; charset=utf-8", "text/csv; charset=utf-8",
                 "application/json"}
# Literal values that look like real secrets; dashboard warns to use {{secret:...}} instead.
SECRET_LIKE = [
    (re.compile(r"(?i)(password|passwd|pass|secret|token|api[_-]?key)\s*[=:]\s*[\"']?(?!\{\{)[^\s\"'{]{6,}"),
     "มีรหัสผ่านหรือ key ที่พิมพ์เอง ควรใช้ค่าสุ่ม {{secret:password:...}} หรือ {{secret:token:...}} แทน"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "มี private key จริงในเนื้อหา"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "มีรูปแบบ AWS Access Key จริง"),
]


def _clean(raw: dict) -> dict:
    """Keep only known fields so a saved file never carries unexpected data."""
    if not isinstance(raw, dict):
        raise ValueError("definition_must_be_object")
    nodes = []
    for item in raw.get("nodes") or []:
        if not isinstance(item, dict):
            raise ValueError("node_must_be_object")
        node = {k: item[k] for k in ("id", "kind", "path", "title", "content_type", "next", "filler",
                                     "requires_header") if k in item}
        if "body_lines" in item and "body" not in item:
            lines = item["body_lines"]
            node["body"] = "\n".join(lines) + "\n" if isinstance(lines, list) else ""
        elif "body" in item:
            node["body"] = item["body"]
        nodes.append(node)
    return {"id": raw.get("id"), "title": raw.get("title"), "description": raw.get("description", ""),
            "protocol": raw.get("protocol"), "entry": raw.get("entry") or [], "nodes": nodes}


def check(raw: dict, config: RabbitConfig) -> dict:
    """Validate a draft. Returns errors (block saving), warnings and computed depths."""
    errors, warnings = [], []
    try:
        data = _clean(raw)
    except ValueError as exc:
        return {"errors": [str(exc)], "warnings": [], "depths": {}}
    if not isinstance(data["title"], str) or not data["title"].strip() or len(data["title"]) > MAX_TITLE:
        errors.append("ต้องมีชื่อฉาก ยาวไม่เกิน 120 ตัวอักษร")
    if not isinstance(data["description"], str) or len(data["description"]) > MAX_DESCRIPTION:
        errors.append("คำอธิบายยาวไม่เกิน 600 ตัวอักษร")
    if len(data["nodes"]) > MAX_NODES:
        errors.append(f"มีได้ไม่เกิน {MAX_NODES} จุดต่อฉาก")
    for node in data["nodes"]:
        label = node.get("path") or node.get("id")
        if not isinstance(node.get("path"), str) or not PATH_PATTERN.match(node["path"]):
            errors.append(f"{label}: path ต้องขึ้นต้นด้วย / และใช้ตัวอักษรอังกฤษ ตัวเลข หรือ . _ - / เท่านั้น")
        body = node.get("body", "")
        if not isinstance(body, str) or len(body) > MAX_BODY:
            errors.append(f"{label}: เนื้อหายาวเกิน {MAX_BODY // 1024} KB")
            continue
        if node.get("content_type") and node["content_type"] not in CONTENT_TYPES:
            errors.append(f"{label}: ชนิดเนื้อหาไม่รองรับ")
        if node.get("kind") == "people_api" and not (body.strip().isdigit() and 1 <= int(body) <= 200):
            errors.append(f"{label}: API รายชื่อต้องระบุจำนวนคน 1–200")
        header = node.get("requires_header") or {}
        if header and (set(header) != {"X-API-Key"} or node.get("kind") not in {"api", "people_api"}):
            errors.append(f"{label}: รองรับเฉพาะ X-API-Key บนจุดชนิด API")
        literal = re.sub(r"\{\{[^{}]*\}\}", "", body)
        for pattern, message in SECRET_LIKE:
            if pattern.search(literal):
                warnings.append(f"{label}: {message}")
                break
    try:
        scenario = scenario_mod.parse(data)
    except scenario_mod.ScenarioError as exc:
        message = str(exc)
        for node in data["nodes"]:
            if isinstance(node.get("id"), str) and isinstance(node.get("path"), str):
                message = message.replace(f"'{node['id']}'", node["path"])
        errors.append(_thai(message))
        return {"errors": errors, "warnings": warnings, "depths": {}}
    builtin = {sid for sid, item in scenario_mod.available().items()}
    if scenario.id in builtin:
        errors.append("รหัสฉากซ้ำกับเทมเพลต ใช้ปุ่ม 'ใช้เป็นต้นแบบ' เพื่อสร้างสำเนา")
    errors += [_thai(p) for p in scenario_mod.check_limits(scenario, config.limits)]
    errors += [_thai(p) for p in scenario_mod.check_templates(scenario, config.organization)]
    selected = scenario.id in set(config.data["scenarios"]["web"]) | {config.data["scenarios"].get("shell")}
    if scenario.protocol == "web":
        try:
            faker = config.deployment_faker()
            mine = {n.path for n in scenario_mod.resolve_paths(scenario, faker).nodes.values()}
            for other in config.selected("web"):
                if other.id == scenario.id:
                    continue
                clash = mine & {n.path for n in other.nodes.values()}
                if clash:
                    message = (f"path {', '.join(sorted(clash)[:4])}{' …' if len(clash) > 4 else ''} ซ้ำกับฉาก {other.title}"
                               " ที่เปิดใช้อยู่ ให้เปลี่ยน path หรือยกเลิกฉากนั้นก่อนเปิดใช้ฉากนี้")
                    (errors if selected else warnings).append(message)
        except (ValueError, KeyError) as exc:
            errors.append(_thai(str(exc)))
    for node in scenario.nodes.values():
        linked = {expr[5:] for expr in placeholders(node.body) if expr.startswith("node:")}
        missing = [n for n in node.next if n not in linked and scenario.nodes[n].path_template not in node.body]
        if node.kind not in {"listing", "dir", "form"} and missing:
            names = ", ".join(scenario.nodes[n].path_template for n in missing)
            warnings.append(f"{node.path_template}: ชี้ไปที่ {names} แต่เนื้อหายังไม่มีเบาะแสบอกทาง "
                            "กดปุ่ม 'แทรกเบาะแสไปยัง' เพื่อใส่ path ลงในเนื้อหา")
    return {"errors": errors, "warnings": warnings,
            "depths": {n.id: n.depth for n in scenario.nodes.values()}, "selected": selected}


def _thai(message: str) -> str:
    message = re.sub(r"^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)?: ", "", message)
    replacements = [("unreachable nodes", "จุดที่ไม่มีเบาะแสพาไปถึง"), ("depth", "ความลึก"),
                    ("branches", "ทางแยก"), ("> max_depth", "เกินความลึกสูงสุด"),
                    ("> max_branches", "เกินทางแยกสูงสุด"), ("duplicate path", "path ซ้ำ"),
                    ("entry must list existing node ids", "ต้องมีจุดเริ่มอย่างน้อย 1 จุด"),
                    ("placeholder", "ค่าอัตโนมัติ")]
    for old, new in replacements:
        message = message.replace(old, new)
    return message


def new_id() -> str:
    return "custom-" + secrets.token_hex(3)


def definition(config: RabbitConfig, scenario_id: str) -> dict:
    catalog = config.all_scenarios()
    if scenario_id not in catalog:
        raise ValueError("scenario_not_found")
    item = catalog[scenario_id]
    data = _clean(item.raw)
    data["builtin"] = item.builtin
    return data


def save(config: RabbitConfig, raw: dict) -> dict:
    report = check(raw, config)
    if report["errors"]:
        raise ValueError("scenario_invalid: " + "; ".join(report["errors"][:5]))
    data = _clean(raw)
    directory = config.custom_dir
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{data['id']}.json"
    if path.is_file():
        backups = directory / ".backups"
        backups.mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        (backups / f"{data['id']}-{stamp}-{secrets.token_hex(2)}.json").write_bytes(path.read_bytes())
    temporary = path.with_name(path.name + "." + secrets.token_hex(4) + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    return {"ok": True, "id": data["id"], "warnings": report["warnings"]}


def delete(config: RabbitConfig, scenario_id: str) -> dict:
    if not isinstance(scenario_id, str) or not scenario_mod.ID_PATTERN.match(scenario_id):
        raise ValueError("invalid_scenario_id")
    selected = set(config.data["scenarios"]["web"]) | {config.data["scenarios"].get("shell")}
    if scenario_id in selected:
        raise ValueError("ฉากนี้กำลังใช้งานอยู่ ยกเลิกการเลือกและบันทึกการตั้งค่าก่อนลบ")
    path = config.custom_dir / f"{scenario_id}.json"
    if not path.is_file():
        raise ValueError("ลบได้เฉพาะฉากที่ผู้ใช้สร้างเอง")
    backups = config.custom_dir / ".backups"
    backups.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    os.replace(path, backups / f"{scenario_id}-{stamp}-deleted.json")
    return {"ok": True}
