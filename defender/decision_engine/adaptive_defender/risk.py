from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from .models import Decision, Event


@dataclass
class SourceState:
    score: float
    updated: datetime
    scan_until: datetime | None = None
    ssh_until: datetime | None = None
    telnet_until: datetime | None = None


class RiskEngine:
    def __init__(self, thresholds: dict[str, float], decay_per_minute: float, expiry_seconds: int,
                 clock: Callable[[], datetime] | None = None):
        self.thresholds = thresholds
        self.decay_per_minute = decay_per_minute
        self.expiry_seconds = expiry_seconds
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.states: dict[str, SourceState] = {}
        self.seen: dict[str, datetime] = {}

    def _prune(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.expiry_seconds)
        self.seen = {key: value for key, value in self.seen.items() if value >= cutoff}

    def decide(self, event: Event) -> Decision | None:
        now = self.clock()
        self._prune(now)
        if event.event_id in self.seen:
            return None
        self.seen[event.event_id] = now
        state = self.states.get(event.source_ip, SourceState(0.0, now))
        elapsed_minutes = max(0.0, (now - state.updated).total_seconds() / 60)
        state.score = max(0.0, state.score - elapsed_minutes * self.decay_per_minute)
        severity_points = {1: 35, 2: 25, 3: 12}.get(event.severity, 8)
        protocol_points = {"scan": 25, "ssh": 10, "telnet": 10, "http": 5, "tls": 5}.get(event.protocol, 3)
        reasons = [f"severity={event.severity}:+{severity_points}", f"protocol={event.protocol}:+{protocol_points}"]
        if event.signature_id == 2200301 or event.protocol == "scan":
            state.scan_until = now + timedelta(seconds=self.expiry_seconds)
        if event.protocol == "ssh":
            state.ssh_until = now + timedelta(seconds=self.expiry_seconds)
        if event.protocol == "telnet":
            state.telnet_until = now + timedelta(seconds=self.expiry_seconds)
        if event.protocol in {"http", "tls"} and state.scan_until and state.scan_until > now:
            protocol_points += 20
            reasons.append("active_scan_history:+20")
        if event.protocol in {"http", "tls"} and state.ssh_until and state.ssh_until > now:
            protocol_points += 10
            reasons.append("active_ssh_history:+10")
        if event.protocol in {"http", "tls"} and state.telnet_until and state.telnet_until > now:
            protocol_points += 10
            reasons.append("active_telnet_history:+10")
        state.score = min(100.0, state.score + severity_points + protocol_points)
        state.updated = now
        self.states[event.source_ip] = state
        if state.score >= self.thresholds["temporary_block"]:
            action, profile = "temporary_block", "none"
        elif state.score >= self.thresholds["redirect"]:
            if event.protocol == "ssh":
                action, profile = "redirect_ssh", "cowrie"
            elif event.protocol == "telnet":
                action, profile = "redirect_telnet", "telnet"
            else:
                action = "redirect_web"
                profile = "phpmyadmin" if event.signature_id == 2200002 else "wordpress"
        elif state.score >= self.thresholds["monitor"]:
            action, profile = "monitor", "real"
        else:
            action, profile = "allow", "real"
        expiry = now + timedelta(seconds=self.expiry_seconds)
        return Decision(
            event_id=event.event_id, source_ip=event.source_ip, protocol=event.protocol,
            signature_id=event.signature_id, severity=event.severity,
            risk_score=round(state.score, 2), action=action, profile=profile,
            reason=";".join(reasons), start_time=now.isoformat(), expiry=expiry.isoformat(),
        )
