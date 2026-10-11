"""Backend data sets for the company web app.

`load(name)` returns the data object the app reads. `real` is the production
data; `decoy` is isolated fake data for the honeypot. Both expose the same
interface, so the same application code runs against either.
"""
from __future__ import annotations

import importlib


def load(name: str):
    name = (name or "decoy").strip().lower()
    if name not in {"real", "decoy"}:
        raise ValueError(f"unknown backend: {name!r}")
    return importlib.import_module(f"{__name__}.{name}").Backend()
