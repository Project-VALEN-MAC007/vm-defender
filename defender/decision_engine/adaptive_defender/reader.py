from __future__ import annotations

import json
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Iterator


@dataclass(frozen=True)
class PendingRecord:
    record: dict
    inode: int
    offset: int


class EveReader:
    """Incremental JSON-lines reader with inode/offset rotation handling."""

    def __init__(self, eve_path: Path, checkpoint_path: Path):
        self.eve_path = eve_path
        self.checkpoint_path = checkpoint_path

    def _checkpoint(self) -> dict[str, int]:
        try:
            raw = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            return {"inode": int(raw["inode"]), "offset": int(raw["offset"])}
        except (FileNotFoundError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return {"inode": 0, "offset": 0}

    def _save(self, inode: int, offset: int) -> None:
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.checkpoint_path.with_suffix(self.checkpoint_path.suffix + ".tmp")
        temporary.write_text(json.dumps({"inode": inode, "offset": offset}) + "\n", encoding="utf-8")
        os.replace(temporary, self.checkpoint_path)

    def pending_records(self) -> Iterator[PendingRecord]:
        stat = self.eve_path.stat()
        checkpoint = self._checkpoint()
        offset = checkpoint["offset"]
        if checkpoint["inode"] != stat.st_ino or stat.st_size < offset:
            offset = 0
        with self.eve_path.open("r", encoding="utf-8") as stream:
            stream.seek(offset)
            while True:
                before = stream.tell()
                line = stream.readline()
                if not line:
                    break
                if not line.endswith("\n"):
                    stream.seek(before)
                    break
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    self._save(stat.st_ino, stream.tell())
                    continue
                yield PendingRecord(record, stat.st_ino, stream.tell())

    def commit(self, pending: PendingRecord) -> None:
        self._save(pending.inode, pending.offset)

    def records(self) -> Iterator[dict]:
        """Compatibility iterator that acknowledges records after consumption."""
        for pending in self.pending_records():
            yield pending.record
            self.commit(pending)
