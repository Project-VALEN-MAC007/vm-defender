from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
from typing import Any


ALLOWED_ACTIONS = {"allow", "monitor", "redirect_web", "redirect_ssh", "redirect_telnet", "temporary_block"}


@dataclass(frozen=True)
class Settings:
    eve_path: Path
    checkpoint_path: Path
    audit_path: Path
    nginx_map_path: Path
    dry_run: bool
    decay_per_minute: float
    expiry_seconds: int
    thresholds: dict[str, float]
    nft_family: str = "inet"
    nft_table: str = "adaptive_defender"
    bind_host: str = "127.0.0.1"
    bind_port: int = 9090


def _path(value: Any, field: str, base: Path) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty path")
    path = Path(value)
    return path if path.is_absolute() else (base / path).resolve()


def load_settings(path: str | Path) -> Settings:
    config_path = Path(path).resolve()
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    base = config_path.parent
    thresholds = raw.get("thresholds", {})
    expected = {"monitor", "redirect", "temporary_block"}
    if set(thresholds) != expected:
        raise ValueError(f"thresholds must contain exactly {sorted(expected)}")
    values = [float(thresholds[key]) for key in ("monitor", "redirect", "temporary_block")]
    if not (0 <= values[0] < values[1] < values[2] <= 100):
        raise ValueError("thresholds must increase and stay within 0..100")
    bind_host = str(raw.get("bind_host", "127.0.0.1"))
    if not ipaddress.ip_address(bind_host).is_loopback:
        raise ValueError("dashboard bind_host must be loopback")
    expiry = int(raw.get("expiry_seconds", 1800))
    if not 1 <= expiry <= 86400:
        raise ValueError("expiry_seconds must be 1..86400")
    return Settings(
        eve_path=_path(raw.get("eve_path"), "eve_path", base),
        checkpoint_path=_path(raw.get("checkpoint_path"), "checkpoint_path", base),
        audit_path=_path(raw.get("audit_path"), "audit_path", base),
        nginx_map_path=_path(raw.get("nginx_map_path"), "nginx_map_path", base),
        dry_run=bool(raw.get("dry_run", True)),
        decay_per_minute=float(raw.get("decay_per_minute", 1.0)),
        expiry_seconds=expiry,
        thresholds={key: float(value) for key, value in thresholds.items()},
        nft_family=str(raw.get("nft_family", "inet")),
        nft_table=str(raw.get("nft_table", "adaptive_defender")),
        bind_host=bind_host,
        bind_port=int(raw.get("bind_port", 9090)),
    )
