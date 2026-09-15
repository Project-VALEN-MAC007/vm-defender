from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import subprocess
from typing import Callable


class NginxMapAdapter:
    def __init__(self, path: Path, dry_run: bool = True,
                 validator: Callable[[Path], bool] | None = None,
                 reloader: Callable[[], bool] | None = None):
        self.path = path
        self.dry_run = dry_run
        self.validator = validator
        self.reloader = reloader
        if not dry_run and validator is None:
            raise ValueError("apply mode requires an nginx config validator")

    def render(self, entries: dict[str, str]) -> str:
        allowed = {"real", "wordpress", "phpmyadmin"}
        lines = ["# generated atomically; do not edit", "default real;"]
        for address, profile in sorted(entries.items()):
            ipaddress.ip_address(address)
            if profile not in allowed:
                raise ValueError(f"unsupported web profile: {profile}")
            lines.append(f"{address} {profile};")
        return "\n".join(lines) + "\n"

    def update(self, entries: dict[str, str]) -> str:
        content = self.render(entries)
        if self.dry_run:
            return content
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists()
        previous = self.path.read_bytes() if existed else b""
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, self.path)
        if not self.validator(self.path):
            rollback = self.path.with_suffix(self.path.suffix + ".rollback")
            if existed:
                rollback.write_bytes(previous)
                os.replace(rollback, self.path)
            else:
                self.path.unlink()
            raise RuntimeError("nginx validation failed; map rolled back")
        if self.reloader and not self.reloader():
            rollback = self.path.with_suffix(self.path.suffix + ".rollback")
            if existed:
                rollback.write_bytes(previous)
                os.replace(rollback, self.path)
                if self.validator:
                    self.validator(self.path)
            else:
                self.path.unlink()
            raise RuntimeError("nginx reload failed; map rolled back")
        return content


class NftSetAdapter:
    def __init__(self, family: str, table: str, dry_run: bool = True):
        if family not in {"ip", "inet"}:
            raise ValueError("nft family must be ip or inet")
        self.family, self.table, self.dry_run = family, table, dry_run

    def command(self, set_name: str, address: str, timeout_seconds: int) -> list[str]:
        ipaddress.ip_address(address)
        if set_name not in {"ssh_redirect", "telnet_redirect", "temporary_block"}:
            raise ValueError("unsupported nft set")
        if not 1 <= timeout_seconds <= 86400:
            raise ValueError("timeout out of bounds")
        return ["nft", "add", "element", self.family, self.table, set_name,
                "{", address, "timeout", f"{timeout_seconds}s", "}"]

    def add(self, set_name: str, address: str, timeout_seconds: int) -> list[str]:
        command = self.command(set_name, address, timeout_seconds)
        if not self.dry_run:
            subprocess.run(command, check=True, capture_output=True, text=True)
        return command
