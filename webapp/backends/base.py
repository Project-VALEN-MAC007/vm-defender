"""Shared backend behaviour. A backend supplies the company name, news,
customer accounts and their shipments, and records contact submissions."""
from __future__ import annotations

import hashlib
import hmac
import threading


class BaseBackend:
    company = "Acme Logistics"
    name = "base"
    # list[dict(slug,title,date,body)]
    articles: list = []
    # username -> dict(password, display_name, shipments=list[dict])
    accounts: dict = {}
    # Decoy only: account shown for a well-formed session cookie this server never
    # issued (e.g. one carried over from the production site after a redirect).
    session_fallback_user: str | None = None

    def __init__(self):
        self._lock = threading.Lock()
        self._contacts: list = []

    def article(self, slug: str):
        return next((a for a in self.articles if a["slug"] == slug), None)

    def verify(self, username: str, password: str):
        account = self.accounts.get((username or "").strip())
        if not account:
            return None
        # Constant-time compare; passwords here are lab fixtures, never real secrets.
        if not hmac.compare_digest(account["password"], password or ""):
            return None
        return account

    def record_contact(self, name: str, email: str, message: str) -> None:
        with self._lock:
            self._contacts.append({"name": name[:100], "email": email[:120], "message": message[:2000]})

    def contact_count(self) -> int:
        with self._lock:
            return len(self._contacts)
