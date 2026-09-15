from __future__ import annotations

import csv
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import subprocess
from urllib.parse import urlparse


FIELDS = ["start_time", "source_ip", "protocol", "signature_id", "severity",
          "risk_score", "action", "profile", "reason", "expiry"]

ALERT_FIELDS = ["timestamp", "src_ip", "src_port", "dest_ip", "dest_port",
                "proto", "app_proto", "signature_id", "signature", "category",
                "severity", "http_url", "http_user_agent"]

# Suricata eve.json locations searched in order. Absolute host paths are read
# only when readable; missing or unreadable files are skipped without error.
DEFAULT_EVE_PATHS = ("/var/log/suricata/eve.json",
                     "evidence/test-results/eve.json",
                     "evidence/test-results/http-positive-run1/eve.json",
                     "evidence/test-results/http-benign-run1/eve.json")


def read_alerts(paths, limit: int = 500) -> list[dict]:
    """Return real Suricata alert events, newest first. No data is synthesised."""
    rows: list[dict] = []
    for candidate in paths:
        path = Path(candidate)
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "alert":
                continue
            alert = event.get("alert") or {}
            http = event.get("http") or {}
            rows.append({
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
            })
    rows.sort(key=lambda row: row.get("timestamp") or "", reverse=True)
    return rows[:limit]


def alerts_csv_export(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=ALERT_FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def read_decisions(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("status") != "error":
            rows.append(item)
    return rows


def summary(rows: list[dict]) -> dict:
    by_action: dict[str, int] = {}
    by_protocol: dict[str, int] = {}
    for row in rows:
        by_action[row.get("action", "unknown")] = by_action.get(row.get("action", "unknown"), 0) + 1
        by_protocol[row.get("protocol", "unknown")] = by_protocol.get(row.get("protocol", "unknown"), 0) + 1
    return {"total": len(rows), "by_action": by_action, "by_protocol": by_protocol}


def csv_export(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def live_status() -> dict:
    services = {}
    for label, unit in (("suricata", "suricata"), ("nginx", "nginx"),
                        ("decision_engine", "adaptive-defender")):
        result = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
        services[label] = result.stdout.strip() or "not-found"
    services["backends"] = {"real":"unknown", "wordpress":"unknown",
                            "phpmyadmin":"unknown", "cowrie":"unknown",
                            "telnet":"unknown"}
    return services


def handler_factory(audit_path: Path, status_path: Path, eve_paths: tuple = DEFAULT_EVE_PATHS):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            rows = read_decisions(audit_path)
            alerts = read_alerts(eve_paths)
            route = urlparse(self.path).path

            if route == "/api/decisions.json":
                self._send("application/json", json.dumps(rows).encode())
            elif route == "/api/decisions.csv":
                body = csv_export(rows).encode()
                self._send_download("text/csv; charset=utf-8", body, "decisions.csv")
            elif route == "/api/alerts.json":
                self._send("application/json", json.dumps(alerts).encode())
            elif route == "/api/alerts.csv":
                body = alerts_csv_export(alerts).encode()
                self._send_download("text/csv; charset=utf-8", body, "alerts.csv")
            elif route == "/api/summary.json":
                summary_data = summary(rows)
                summary_data["total_alerts"] = len(alerts)
                self._send("application/json", json.dumps(summary_data).encode())
            elif route == "/api/status.json":
                status = json.loads(status_path.read_text()) if status_path.exists() else live_status()
                self._send("application/json", json.dumps(status).encode())
            elif route == "/":
                # Serve the new HTML dashboard
                static_dir = Path(__file__).parent / "static"
                dashboard_file = static_dir / "dashboard.html"
                if dashboard_file.exists():
                    body = dashboard_file.read_bytes()
                    self._send("text/html; charset=utf-8", body)
                else:
                    # Fallback to simple dashboard
                    body = ("<!doctype html><meta charset=utf-8><title>VM-Defender</title>"
                            "<h1>Adaptive Honeypot — VM-Defender</h1>"
                            "<p>Loopback-only dashboard. JSON/CSV exports are under <code>/api/</code>.</p>"
                            f"<pre>{json.dumps({'summary': summary(rows), 'latest': rows[-20:]}, indent=2)}</pre>")
                    self._send("text/html; charset=utf-8", body.encode())
            else:
                self.send_error(404)

        def _send(self, content_type: str, body: bytes):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_download(self, content_type: str, body: bytes, filename: str):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return
    return Handler


def serve(audit_path: Path, status_path: Path, host: str = "127.0.0.1", port: int = 9090, eve_paths: tuple = DEFAULT_EVE_PATHS):
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("dashboard may bind only to loopback")
    ThreadingHTTPServer((host, port), handler_factory(audit_path, status_path, eve_paths)).serve_forever()
