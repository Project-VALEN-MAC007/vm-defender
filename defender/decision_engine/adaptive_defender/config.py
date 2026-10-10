from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
from typing import Any


ALLOWED_ACTIONS = {"allow", "monitor", "redirect_web", "redirect_ssh", "redirect_telnet"}


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
    web_profile: str = "wordpress"
    config_path: Path | None = None
    # Signatures that only ever raise an alert (network scanning). Their score
    # still counts towards later events from the same source.
    scan_only_signatures: frozenset[int] = frozenset({2017616})
    # Optional file the Dashboard may write. When present it overrides the
    # thresholds in the main config, so /etc can stay read-only for the Dashboard.
    thresholds_path: Path | None = None


def _path(value: Any, field: str, base: Path) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty path")
    path = Path(value)
    return path if path.is_absolute() else (base / path).resolve()


def validate_thresholds(thresholds: Any) -> dict[str, float]:
    expected = {"monitor", "redirect"}
    if not isinstance(thresholds, dict) or set(thresholds) != expected:
        raise ValueError(f"thresholds must contain exactly {sorted(expected)}")
    values = {}
    for key in ("monitor", "redirect"):
        value = thresholds[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("thresholds must be numbers")
        values[key] = float(value)
    if not (0 <= values["monitor"] < values["redirect"] <= 100):
        raise ValueError("thresholds must increase and stay within 0..100")
    return values


def load_thresholds_override(path: Path) -> dict[str, float] | None:
    """Thresholds written by the Dashboard, or None when the file does not exist."""
    if not path.is_file():
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    return validate_thresholds(raw.get("thresholds") if isinstance(raw, dict) else None)


def load_settings(path: str | Path) -> Settings:
    config_path = Path(path).resolve()
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    base = config_path.parent
    thresholds = validate_thresholds(raw.get("thresholds", {}))
    thresholds_path = None
    if raw.get("thresholds_path") is not None:
        thresholds_path = _path(raw.get("thresholds_path"), "thresholds_path", base)
        override = load_thresholds_override(thresholds_path)
        if override is not None:
            thresholds = override
    scan_only = raw.get("scan_only_signatures", [2017616])
    if not isinstance(scan_only, list) or any(isinstance(sid, bool) or not isinstance(sid, int) or sid <= 0 for sid in scan_only):
        raise ValueError("scan_only_signatures must be a list of positive SIDs")
    bind_host = str(raw.get("bind_host", "127.0.0.1"))
    if not ipaddress.ip_address(bind_host).is_loopback:
        raise ValueError("dashboard bind_host must be loopback")
    expiry = int(raw.get("expiry_seconds", 1800))
    web_profile = str(raw.get("web_profile", "wordpress"))
    if web_profile not in {"wordpress", "phpmyadmin", "snare", "rabbithole"}:
        raise ValueError("unsupported web_profile")
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
        thresholds=thresholds,
        nft_family=str(raw.get("nft_family", "inet")),
        nft_table=str(raw.get("nft_table", "adaptive_defender")),
        bind_host=bind_host,
        bind_port=int(raw.get("bind_port", 9090)),
        web_profile=web_profile,
        config_path=config_path,
        scan_only_signatures=frozenset(scan_only),
        thresholds_path=thresholds_path,
    )
