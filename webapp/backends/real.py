"""Production data. On the real server this module is replaced with the
organisation's actual data source; the values here are lab placeholders so the
project runs end to end. Nothing here is a real credential."""
from __future__ import annotations

from .base import BaseBackend


class Backend(BaseBackend):
    name = "real"
    company = "Acme Logistics"
    articles = [
        {"slug": "q3-capacity", "title": "Added road capacity for Q3 peak", "date": "2026-09-18",
         "body": "We have expanded our line-haul fleet to keep transit times steady during the Q3 peak."},
        {"slug": "port-schedule", "title": "Updated port cut-off schedule", "date": "2026-08-30",
         "body": "Revised cut-off times for sea freight take effect next month. Please check your bookings."},
        {"slug": "iso-audit", "title": "Passed annual ISO 9001 audit", "date": "2026-07-12",
         "body": "Our quality management system passed its annual external audit with no major findings."},
    ]
    accounts = {
        "acme-ops": {"password": "lab-real-not-a-secret-1", "display_name": "Acme Operations",
                     "shipments": [
                         {"ref": "AL-204915", "origin": "Bangkok", "destination": "Chiang Mai",
                          "status": "In transit", "eta": "2026-10-11"},
                         {"ref": "AL-204880", "origin": "Laem Chabang", "destination": "Singapore",
                          "status": "At port", "eta": "2026-10-14"}]},
    }
