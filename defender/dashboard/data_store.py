from __future__ import annotations

from collections import deque
import json
from pathlib import Path
import threading
from typing import Callable


class JsonlTail:
    """Incrementally reads complete JSONL records and keeps a bounded snapshot."""

    def __init__(self, paths: tuple[Path, ...], transform: Callable[[dict, Path], dict | None],
                 maximum_rows: int = 5000):
        self.paths = paths
        self.transform = transform
        self.maximum_rows = maximum_rows
        self._states: dict[Path, dict] = {}
        self._lock = threading.Lock()

    def rows(self) -> list[dict]:
        with self._lock:
            for path in self.paths:
                self._refresh_path(path)
            rows = [row for state in self._states.values() for row in state["rows"]]
        rows.sort(key=lambda row: row.get("timestamp") or row.get("start_time") or "", reverse=True)
        return rows[:self.maximum_rows]

    def _refresh_path(self, path: Path) -> None:
        try:
            stat = path.stat()
        except OSError:
            return
        state = self._states.get(path)
        if state is None or state["inode"] != stat.st_ino or stat.st_size < state["offset"]:
            state = {"inode": stat.st_ino, "offset": 0, "rows": deque(maxlen=self.maximum_rows)}
            self._states[path] = state
        if stat.st_size == state["offset"]:
            return
        try:
            with path.open("rb") as stream:
                stream.seek(state["offset"])
                while True:
                    before = stream.tell()
                    line = stream.readline()
                    if not line:
                        break
                    if not line.endswith(b"\n"):
                        stream.seek(before)
                        break
                    state["offset"] = stream.tell()
                    try:
                        raw = json.loads(line.decode("utf-8", errors="replace"))
                    except json.JSONDecodeError:
                        continue
                    row = self.transform(raw, path)
                    if row is not None:
                        state["rows"].append(row)
        except OSError:
            return


def alert_transform(event: dict, path: Path) -> dict | None:
    if event.get("event_type") != "alert":
        return None
    alert = event.get("alert") or {}
    http = event.get("http") or {}
    return {
        "timestamp": event.get("timestamp"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "app_proto": event.get("app_proto"),
        "signature_id": alert.get("signature_id"),
        "signature": alert.get("signature"),
        "category": alert.get("category"),
        "severity": alert.get("severity"),
        "http_url": http.get("url"),
        "http_user_agent": http.get("http_user_agent"),
        "source_file": str(path),
    }


def decision_transform(item: dict, _: Path) -> dict | None:
    return None if item.get("status") == "error" else item
