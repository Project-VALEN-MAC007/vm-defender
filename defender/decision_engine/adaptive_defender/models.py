from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from typing import Any


# Decrypted HTTPS is inspected on a loopback hop behind the Nginx TLS edge
# (see defender/nginx/adaptive-honeypot.conf.template). Alerts there carry
# 127.0.0.2 as the source; the real client comes from the X-Trap-Client-IP
# header that only the edge sets, which Suricata reports as the "xff" field.
TLS_INSPECT_PORT = 18443
TRUSTED_CLIENT_HEADER = "X-Trap-Client-IP"


def tls_inspection_client(raw: dict[str, Any]) -> str | None:
    """Real client IP for an alert seen on the loopback HTTPS inspection hop,
    or None when the alert is not from that hop. Raises ValueError when the
    alert is from the hop but carries no valid client address."""
    try:
        dest_port = int(raw.get("dest_port") or 0)
        dest = ipaddress.ip_address(str(raw.get("dest_ip", "")))
    except ValueError:
        return None
    if dest_port != TLS_INSPECT_PORT or str(dest) != "127.0.0.1":
        return None
    if raw.get("src_ip") != "127.0.0.2" or raw.get("in_iface") != "lo":
        raise ValueError("TLS inspection alert is not from the trusted edge hop")
    # The edge overwrites the header with one address. Lists are ambiguous
    # and must never select a client supplied address.
    # Suricata 7 extra-data for alert output is stored inside alert.xff.
    client = str((raw.get("alert") or {}).get("xff") or raw.get("xff") or
                 (raw.get("http") or {}).get("xff") or "").strip()
    address = ipaddress.ip_address(client)  # ValueError when missing/invalid
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError("TLS inspection alert has invalid client address")
    return str(address)


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
        # Only alerts from the loopback inspection hop may use the client
        # header; on the outer interface a client could forge it.
        tls_client = tls_inspection_client(raw)
        if tls_client is not None:
            source_ip = tls_client
            destination_port = 443
        # These ET Open rules inspect server responses. Attribute the event
        # to the client, rather than redirecting the Telnet server itself.
        if signature_id in {2100492, 2101251}:
            if int(raw.get("src_port") or 0) != 23:
                raise ValueError("ET Telnet response alert must originate on port 23")
            source_ip = str(raw.get("dest_ip", ""))
            ipaddress.ip_address(source_ip)
            destination_port = 23
        protocol = "https" if tls_client is not None else \
            str(raw.get("app_proto") or raw.get("proto") or "unknown").lower()
        metadata_protocol = (alert.get("metadata") or {}).get("protocol")
        if isinstance(metadata_protocol, list) and metadata_protocol:
            metadata_protocol = metadata_protocol[0]
        if protocol in {"tcp", "unknown"} and metadata_protocol:
            protocol = str(metadata_protocol).lower()
        if protocol in {"tcp", "unknown"}:
            if destination_port == 22 or signature_id in {2001219, 2006546}:
                protocol = "ssh"
            elif destination_port == 23 or signature_id in {2100492, 2101251}:
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
