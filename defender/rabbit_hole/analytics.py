"""Turn Rabbit Hole events into tracking windows and summary numbers.

Rules (from the TRAP document, section 1.3.3):

* A tracking window starts at the first successful access to a decoy resource.
* It continues while the gap between activities is at most the idle timeout.
* Its duration is last activity minus first activity; idle time is not added.
* A gap longer than the idle timeout starts a new window, even in the same session.
* A single access is reported as such, without an interaction duration.
* For SSH/Telnet the connection time is reported separately.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
from datetime import datetime, timezone
from statistics import median


def _stamp(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def _bait_hit(event: dict) -> bool:
    """A Rabbit Hole decoy node the attacker actually reached (drives the trail,
    depth and 'followed a clue'). Ordinary pages have no node_id."""
    if not event.get("node_id"):
        return False
    if event.get("event") == "rabbit_hole.web":
        return int(event.get("status") or 0) in {200, 302}
    return True


def _is_visit(event: dict, family: str) -> bool:
    """Whether this event means the attacker was interacting with the honeypot,
    for session/dwell accounting. A web visit is any response the honeypot
    served (landing page, 404 or decoy alike), so a redirected attacker who only
    views the front page still counts; shell dwell still begins at the first
    decoy node, preserving existing Cowrie behaviour."""
    if family == "web":
        return event.get("status") is not None
    return _bait_hit(event)


def windows(events: list, idle_timeout: int, now: datetime | None = None) -> list:
    now = now or datetime.now(timezone.utc)
    groups = defaultdict(list)
    for event in events:
        when = _stamp(event.get("timestamp"))
        if when is None or not event.get("session_id"):
            continue
        family = "web" if event.get("event") == "rabbit_hole.web" else "shell"
        groups[(family, str(event["session_id"]))].append((when, event))
    result = []
    for (family, sid), items in groups.items():
        items.sort(key=lambda pair: pair[0])
        current = None
        last_time = None
        for when, event in items:
            if current is not None and (when - last_time).total_seconds() > idle_timeout:
                current["end_reason"] = "idle_timeout"
                result.append(_finish(current))
                current = None
            if event.get("action") == "session_closed":
                if current is not None:
                    current["connection_seconds"] = event.get("connection_seconds")
                    current["end_reason"] = "session_closed"
                    result.append(_finish(current))
                    current = None
                continue
            if current is None:
                if not _is_visit(event, family):
                    continue
                current = {"family": family, "session_id": sid, "protocol": event.get("protocol"),
                           "source_ip": event.get("source_ip"), "start": when, "end": when,
                           "events": 0, "trail": [], "resources": [], "scenarios": set(),
                           "links": set(), "clues_followed": set(), "limit_reached": False,
                           "denied": 0, "end_reason": None, "connection_seconds": None,
                           "user_agent": event.get("user_agent")}
            current["end"] = when
            current["events"] += 1
            last_time = when
            if event.get("link"):
                current["links"].add(event["link"])
            if event.get("limit_reached"):
                current["limit_reached"] = True
            if event.get("action") == "call_api_denied":
                current["denied"] += 1
            if _bait_hit(event):
                current["scenarios"].add(event.get("scenario"))
                resource = event.get("resource_id") or event.get("node_id")
                if resource not in current["resources"]:
                    current["resources"].append(resource)
                if event.get("followed_clue"):
                    current["clues_followed"].add(resource)
                current["trail"].append({
                    "time": when.isoformat(), "resource": resource, "node_id": event.get("node_id"),
                    "scenario": event.get("scenario"), "depth": event.get("depth"),
                    "action": event.get("action"), "path": event.get("path") or event.get("command"),
                    "clue_from": event.get("clue_from"), "followed_clue": bool(event.get("followed_clue")),
                    "clue_by": event.get("clue_by"), "clue_confidence": event.get("clue_confidence"),
                    "category": event.get("category"), "status": event.get("status")})
        if current is not None:
            if current["limit_reached"]:
                current["end_reason"] = "limit_reached"
            elif (now - current["end"]).total_seconds() > idle_timeout:
                current["end_reason"] = "idle_timeout"
            else:
                current["end_reason"] = "active"
            result.append(_finish(current))
    result.sort(key=lambda w: w["start"], reverse=True)
    return result


def _finish(window: dict) -> dict:
    if window["limit_reached"] and window["end_reason"] != "session_closed":
        window["end_reason"] = "limit_reached"
    single = len(window["trail"]) <= 1 and window["events"] <= 1
    depths = [step["depth"] for step in window["trail"] if step["depth"]]
    start, end = window["start"], window["end"]
    raw_id = f"{window['family']}|{window['session_id']}|{start.isoformat()}"
    identifier = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:20]
    return {
        "id": identifier, "family": window["family"], "protocol": window["protocol"],
        "session_id": window["session_id"], "source_ip": window["source_ip"],
        "user_agent": window["user_agent"],
        "start": start.isoformat(), "end": end.isoformat(),
        "duration_seconds": None if single else round((end - start).total_seconds(), 1),
        "single_access": single, "events": window["events"],
        "resources": len(window["resources"]), "max_depth": max(depths) if depths else 0,
        "clues_followed": len(window["clues_followed"]),
        "followed": bool(window["clues_followed"]),
        "scenarios": sorted(s for s in window["scenarios"] if s),
        "links": sorted(window["links"]), "denied_api_calls": window["denied"],
        "end_reason": window["end_reason"], "connection_seconds": window["connection_seconds"],
        "trail": window["trail"],
    }


def _avg(values):
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 1) if values else None


def summarize(items: list, static_sessions: list | None = None) -> dict:
    by_family = defaultdict(list)
    for item in items:
        key = item["protocol"] if item["family"] == "shell" else "web"
        by_family[key].append(item)

    def block(rows):
        sessions = {r["session_id"] for r in rows}
        followed = {r["session_id"] for r in rows if r["followed"]}
        durations = [r["duration_seconds"] for r in rows if r["duration_seconds"] is not None]
        return {
            "windows": len(rows), "sessions": len(sessions), "sessions_followed": len(followed),
            "follow_rate": round(len(followed) / len(sessions), 3) if sessions else None,
            "single_access": sum(1 for r in rows if r["single_access"]),
            "average_resources": _avg([r["resources"] for r in rows]),
            "average_depth": _avg([r["max_depth"] for r in rows]),
            "max_depth": max((r["max_depth"] for r in rows), default=0),
            "average_duration_seconds": _avg(durations),
            "median_duration_seconds": round(median(durations), 1) if durations else None,
            "max_duration_seconds": max(durations) if durations else None,
            "average_connection_seconds": _avg([r["connection_seconds"] for r in rows
                                                if isinstance(r.get("connection_seconds"), (int, float))]),
        }

    resources = Counter()
    depth_hist = Counter()
    for item in items:
        depth_hist[item["max_depth"]] += 1
        for step in item["trail"]:
            resources[(step["scenario"], step["resource"].split("/")[0])] += 1
    summary = {"overall": block(items),
               "by_protocol": {name: block(rows) for name, rows in sorted(by_family.items())},
               "top_resources": [{"scenario": s, "node_id": n, "count": c}
                                 for (s, n), c in resources.most_common(10)],
               "depth_distribution": {str(k): v for k, v in sorted(depth_hist.items())},
               "end_reasons": dict(Counter(item["end_reason"] for item in items)),
               # Who placed the clues attackers actually followed: Jev, the fallback, or a fixed scenario.
               "followed_clue_by": dict(Counter(step.get("clue_by") or "fixed" for item in items
                                                for step in item["trail"] if step.get("followed_clue")))}
    summary.update(_strategy_view(items, block))
    static = [s for s in (static_sessions or []) if s.get("profile") not in {"rabbithole"}]
    static_durations = [s["dwell_seconds"] for s in static if s.get("actions", 0) > 1]
    rabbit = summary["overall"]["average_duration_seconds"]
    summary["comparison"] = {
        "static_sessions": len(static),
        "static_average_seconds": _avg(static_durations),
        "rabbit_average_seconds": rabbit,
        "note": "เปรียบเทียบได้เมื่อใช้จุดเริ่มต้น ระยะเวลา และกลุ่มผู้ทดสอบเดียวกันเท่านั้น",
    }
    return summary


def placement(item: dict) -> str:
    """Who placed the clues in this window: "jev", "fallback" (planner fallback) or "fixed"."""
    sources = {step.get("clue_by") for step in item["trail"]}
    if "jev" in sources:
        return "jev"
    if "fallback" in sources:
        return "fallback"
    return "fixed"


def _strategy_view(items: list, block) -> dict:
    """Jev-centred figures: the same metrics split by who placed the clues, how deep each group
    got, and which decoys attackers opened at each depth."""
    groups = defaultdict(list)
    for item in items:
        groups[placement(item)].append(item)
    by_strategy = {}
    for name, rows in sorted(groups.items()):
        figures = block(rows)
        hist = Counter(r["max_depth"] for r in rows)
        figures["depth_distribution"] = {str(k): v for k, v in sorted(hist.items())}
        confidences = [step["clue_confidence"] for r in rows for step in r["trail"]
                       if step.get("clue_by") == "jev" and isinstance(step.get("clue_confidence"), (int, float))]
        figures["average_confidence"] = round(sum(confidences) / len(confidences), 3) if confidences else None
        figures["jev_steps"] = sum(1 for r in rows for step in r["trail"] if step.get("clue_by") == "jev")
        by_strategy[name] = figures
    per_depth = defaultdict(Counter)
    categories = {}
    for item in items:
        for step in item["trail"]:
            depth = step.get("depth")
            if not depth:
                continue
            name = (step.get("resource") or "").split("/")[0] or (step.get("path") or "?")
            per_depth[depth][name] += 1
            if step.get("category"):
                categories[name] = step["category"]
    depth_examples = {str(d): [{"resource": n, "count": c, "category": categories.get(n)}
                               for n, c in counter.most_common(3)]
                      for d, counter in sorted(per_depth.items())}
    decisions = []
    for item in items:
        for step in item["trail"]:
            if step.get("followed_clue") and step.get("clue_by") in {"jev", "fallback"}:
                decisions.append({"time": step["time"], "source_ip": item["source_ip"], "window": item["id"],
                                  "family": item["family"], "path": step.get("path"), "category": step.get("category"),
                                  "clue_from": step.get("clue_from"), "depth": step.get("depth"),
                                  "by": step["clue_by"], "confidence": step.get("clue_confidence")})
    decisions.sort(key=lambda d: d["time"], reverse=True)
    return {"by_strategy": by_strategy, "depth_examples": depth_examples,
            "jev_decisions": decisions[:8], "clue_timeline": _timeline(items)}


def _timeline(items: list) -> dict:
    """Followed clues per hour (or per day when the data spans more than two days), split by who placed them."""
    steps = [(_stamp(step["time"]), step.get("clue_by") or "fixed")
             for item in items for step in item["trail"] if step.get("followed_clue")]
    steps = [(t, by) for t, by in steps if t is not None]
    if not steps:
        return {"unit": "hour", "buckets": []}
    first, last = min(t for t, _ in steps), max(t for t, _ in steps)
    unit = "day" if (last - first).total_seconds() > 2 * 86400 else "hour"
    def key(t):
        return (t.replace(hour=0, minute=0, second=0, microsecond=0) if unit == "day"
                else t.replace(minute=0, second=0, microsecond=0)).isoformat()
    buckets = defaultdict(Counter)
    for t, by in steps:
        buckets[key(t)][by] += 1
    return {"unit": unit, "buckets": [{"start": k, "jev": c["jev"], "fallback": c["fallback"], "fixed": c["fixed"]}
                                      for k, c in sorted(buckets.items())][-48:]}
