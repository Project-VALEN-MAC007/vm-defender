from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from typing import Any


def parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: datetime
    source_ip: str
    destination_port: int
    protocol: str
    signature_id: int
    severity: int
    signature: str

    @classmethod
    def from_eve(cls, raw: dict[str, Any]) -> "Event":
        alert = raw.get("alert") or {}
        source_ip = str(raw.get("src_ip", ""))
        ipaddress.ip_address(source_ip)
        destination_port = int(raw.get("dest_port") or 0)
        signature_id = int(alert.get("signature_id") or 0)
        protocol = str(raw.get("app_proto") or raw.get("proto") or "unknown").lower()
        metadata_protocol = (alert.get("metadata") or {}).get("protocol")
        if isinstance(metadata_protocol, list) and metadata_protocol:
            metadata_protocol = metadata_protocol[0]
        if protocol in {"tcp", "unknown"} and metadata_protocol:
            protocol = str(metadata_protocol).lower()
        if protocol in {"tcp", "unknown"}:
            if destination_port == 22 or signature_id in {2200201, 2200202}:
                protocol = "ssh"
            elif destination_port == 23 or signature_id == 2200203:
                protocol = "telnet"
        canonical = {
            "timestamp": raw.get("timestamp"),
            "src_ip": source_ip,
            "dest_port": destination_port,
            "proto": protocol,
            "sid": signature_id,
            "flow_id": raw.get("flow_id"),
        }
        event_id = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return cls(
            event_id=event_id,
            timestamp=parse_time(raw.get("timestamp")),
            source_ip=source_ip,
            destination_port=canonical["dest_port"],
            protocol=canonical["proto"],
            signature_id=canonical["sid"],
            severity=int(alert.get("severity") or 3),
            signature=str(alert.get("signature") or "unknown"),
        )


@dataclass(frozen=True)
class Decision:
    event_id: str
    source_ip: str
    protocol: str
    signature_id: int
    severity: int
    risk_score: float
    action: str
    profile: str
    reason: str
    start_time: str
    expiry: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
