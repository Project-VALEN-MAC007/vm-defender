"""Scenario loading and validation.

A scenario is a small graph of decoy resources. Each node may reveal clues
(``next``) that point to other nodes. Entry nodes are depth 1; every other
node's depth is its shortest distance from an entry node.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import date
import json
from pathlib import Path
import re

from .render import Faker, placeholders, render

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"
WEB_KINDS = {"listing", "file", "api", "form", "people_api"}
SHELL_KINDS = {"dir", "file"}
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class ScenarioError(ValueError):
    pass


@dataclass
class Node:
    id: str
    path_template: str
    kind: str
    body: str = ""
    content_type: str = "text/plain; charset=utf-8"
    next: list = field(default_factory=list)
    requires_header: dict = field(default_factory=dict)
    filler: list = field(default_factory=list)
    status: int = 200
    title: str = ""
    depth: int = 0
    path: str = ""


@dataclass
class Scenario:
    id: str
    title: str
    description: str
    protocol: str
    entry: list
    nodes: dict
    source: str = ""
    builtin: bool = False
    raw: dict = field(default_factory=dict)

    def by_path(self) -> dict:
        return {node.path: node for node in self.nodes.values()}

    def node_paths(self) -> dict:
        return {node.id: node.path for node in self.nodes.values()}

    def max_depth(self) -> int:
        return max((node.depth for node in self.nodes.values()), default=0)


def _body(raw: dict) -> str:
    if "body_lines" in raw:
        lines = raw["body_lines"]
        if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines):
            raise ScenarioError("body_lines must be a list of strings")
        return "\n".join(lines) + ("\n" if lines else "")
    body = raw.get("body", "")
    if not isinstance(body, str):
        raise ScenarioError("body must be a string")
    return body


def parse(raw: dict, source: str = "") -> Scenario:
    if not isinstance(raw, dict):
        raise ScenarioError("scenario must be an object")
    sid = raw.get("id")
    if not isinstance(sid, str) or not ID_PATTERN.match(sid):
        raise ScenarioError("invalid scenario id")
    protocol = raw.get("protocol")
    if protocol not in {"web", "shell"}:
        raise ScenarioError(f"{sid}: protocol must be web or shell")
    kinds = WEB_KINDS if protocol == "web" else SHELL_KINDS
    nodes = {}
    for item in raw.get("nodes") or []:
        nid = item.get("id")
        if not isinstance(nid, str) or not ID_PATTERN.match(nid) or nid in nodes:
            raise ScenarioError(f"{sid}: invalid or duplicate node id {nid!r}")
        kind = item.get("kind")
        if kind not in kinds:
            raise ScenarioError(f"{sid}/{nid}: unsupported kind {kind!r}")
        path = item.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ScenarioError(f"{sid}/{nid}: path must start with /")
        nxt = item.get("next") or []
        if not isinstance(nxt, list) or not all(isinstance(x, str) for x in nxt):
            raise ScenarioError(f"{sid}/{nid}: next must be a list of node ids")
        default_type = {"api": "application/json", "people_api": "application/json",
                        "listing": "text/html; charset=utf-8",
                        "form": "text/html; charset=utf-8"}.get(kind, "text/plain; charset=utf-8")
        nodes[nid] = Node(id=nid, path_template=path, kind=kind, body=_body(item),
                          content_type=str(item.get("content_type") or default_type),
                          next=list(nxt), requires_header=dict(item.get("requires_header") or {}),
                          filler=list(item.get("filler") or []), status=int(item.get("status", 200)),
                          title=str(item.get("title") or ""))
    entry = raw.get("entry") or []
    if not entry or not all(e in nodes for e in entry):
        raise ScenarioError(f"{sid}: entry must list existing node ids")
    for node in nodes.values():
        missing = [n for n in node.next if n not in nodes]
        if missing:
            raise ScenarioError(f"{sid}/{node.id}: unknown next node(s) {missing}")
    scenario = Scenario(id=sid, title=str(raw.get("title") or sid),
                        description=str(raw.get("description") or ""), protocol=protocol,
                        entry=list(entry), nodes=nodes, source=source, raw=raw)
    _assign_depth(scenario)
    return scenario


def _assign_depth(scenario: Scenario) -> None:
    queue = deque()
    for nid in scenario.entry:
        scenario.nodes[nid].depth = 1
        queue.append(nid)
    while queue:
        current = scenario.nodes[queue.popleft()]
        for nid in current.next:
            child = scenario.nodes[nid]
            if child.depth == 0:
                child.depth = current.depth + 1
                queue.append(nid)
    unreachable = [n.id for n in scenario.nodes.values() if n.depth == 0]
    if unreachable:
        raise ScenarioError(f"{scenario.id}: unreachable nodes {unreachable}")


def resolve_paths(scenario: Scenario, faker: Faker) -> Scenario:
    """Render node paths with the deployment-level faker (paths never vary per session)."""
    seen = set()
    for node in scenario.nodes.values():
        node.path = render(node.path_template, faker, {})
        if node.path in seen:
            raise ScenarioError(f"{scenario.id}: duplicate path {node.path}")
        seen.add(node.path)
    return scenario


def check_limits(scenario: Scenario, limits: dict) -> list[str]:
    """Return human-readable problems; empty list means the scenario fits the limits."""
    problems = []
    max_depth = int(limits.get("max_depth", 5))
    max_branches = int(limits.get("max_branches", 2))
    for node in scenario.nodes.values():
        if node.depth > max_depth:
            problems.append(f"{scenario.id}/{node.id}: depth {node.depth} > max_depth {max_depth}")
        if len(node.next) > max_branches:
            problems.append(f"{scenario.id}/{node.id}: {len(node.next)} branches > max_branches {max_branches}")
    return problems


def check_templates(scenario: Scenario, profile: dict) -> list[str]:
    """Render every template once with a throwaway seed to catch unknown placeholders."""
    faker = Faker(b"validation", "validation", profile, date(2026, 1, 1))
    paths = {}
    problems = []
    for node in scenario.nodes.values():
        try:
            paths[node.id] = render(node.path_template, faker, {})
        except (KeyError, ValueError) as exc:
            problems.append(f"{scenario.id}/{node.id}: path placeholder {exc}")
    for node in scenario.nodes.values():
        texts = [node.body] + [str(v) for v in node.requires_header.values()]
        for text in texts:
            for expr in placeholders(text):
                if expr.startswith("ctx."):
                    continue
                try:
                    render("{{" + expr + "}}", faker, paths)
                except (KeyError, ValueError, IndexError) as exc:
                    problems.append(f"{scenario.id}/{node.id}: placeholder {{{{{expr}}}}} {exc}")
    return problems


def load_file(path: Path) -> Scenario:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScenarioError(f"cannot read scenario {path}: {exc}") from exc
    return parse(raw, str(path))


def available(directories=None, errors: list | None = None) -> dict:
    """Built-in templates plus scenarios from extra directories.

    Built-in ids cannot be overridden. A broken file in an extra directory is
    skipped (and reported through ``errors``) so one bad draft never takes the
    whole decoy down.
    """
    result = {}
    for path in sorted(SCENARIO_DIR.glob("*.json")):
        scenario = load_file(path)
        scenario.builtin = True
        result[scenario.id] = scenario
    for directory in [Path(d) for d in (directories or [])]:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.json")):
            try:
                scenario = load_file(path)
            except ScenarioError as exc:
                if errors is not None:
                    errors.append(str(exc))
                continue
            if scenario.id in result:
                if errors is not None:
                    errors.append(f"{path.name}: id {scenario.id} already exists")
                continue
            result[scenario.id] = scenario
    return result
