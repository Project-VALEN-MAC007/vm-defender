"""Decoy data for the honeypot. Same shape as the production backend, but every
value is invented for the lab: fake customers, fake shipments, fake tracking
numbers. It shares nothing with production and holds no real secret, so an
attacker who reaches it learns only fabricated data."""
from __future__ import annotations

from .base import BaseBackend


class Backend(BaseBackend):
    name = "decoy"
    company = "Acme Logistics"
    articles = [
        {"slug": "q3-capacity", "title": "Added road capacity for Q3 peak", "date": "2026-09-18",
         "body": "We have expanded our line-haul fleet to keep transit times steady during the Q3 peak."},
        {"slug": "port-schedule", "title": "Updated port cut-off schedule", "date": "2026-08-30",
         "body": "Revised cut-off times for sea freight take effect next month. Please check your bookings."},
        {"slug": "iso-audit", "title": "Passed annual ISO 9001 audit", "date": "2026-07-12",
         "body": "Our quality management system passed its annual external audit with no major findings."},
    ]
    session_fallback_user = "customer"
    accounts = {
        # Credentials an attacker might guess; all fake, used only to observe behaviour.
        "customer": {"password": "Welcome2026!", "display_name": "Demo Customer",
                     "shipments": [
                         {"ref": "AL-770021", "origin": "Bangkok", "destination": "Hat Yai",
                          "status": "In transit", "eta": "2026-10-12"},
                         {"ref": "AL-769934", "origin": "Rayong", "destination": "Phnom Penh",
                          "status": "Customs", "eta": "2026-10-15"}]},
    }
