"""Template rendering and deterministic fake data for Rabbit Hole scenarios.

Placeholders use ``{{ name }}`` syntax:

``{{org.name}}``                  value from the organisation profile
``{{node:backup-config}}``        path of another node in the same scenario
``{{date}}`` / ``{{date:-3}}``    a stable recent date (offset in days)
``{{secret:password:db}}``        random value kept stable per seed and label
``{{secret:hex:24:api}}``         random hex of the given length
``{{secret:token:api}}``          long API-key style token
``{{secret:int:1000:9999:id}}``   random integer in range
``{{ip:db}}``                     private IP address in the organisation subnet
``{{person:3:email}}``            fields of the N-th fake person
``{{people_csv:12}}``             CSV of fake people
``{{people_json:8}}``             JSON list of fake people

All randomness comes from HMAC(secret, seed + label) so a session that
revisits a resource sees the same content.
"""
from __future__ import annotations

from datetime import date, timedelta
import hashlib
import hmac
import json
import re
import string

PLACEHOLDER = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")

FIRST_NAMES = ["Somchai", "Suda", "Anan", "Pimchanok", "Kittipong", "Nattaya", "Wichai",
               "Ploy", "Thanakorn", "Siriporn", "Chaiwat", "Kanokwan", "Prasert", "Arisa",
               "Narong", "Jiraporn", "Teerapat", "Malee", "Sakda", "Wanida", "Pongsak",
               "Rattana", "Ekkachai", "Duangjai"]
LAST_NAMES = ["Srisuk", "Wongsa", "Chaiyaporn", "Thongdee", "Kaewmanee", "Boonmee",
              "Rattanakul", "Suwannarat", "Phromma", "Jaidee", "Saetang", "Inthasorn",
              "Kongkaew", "Panyasiri", "Somboon", "Meesuk"]
DEPARTMENTS = ["Finance", "IT", "Sales", "HR", "Operations", "Procurement", "Support"]
ROLES = ["staff", "staff", "staff", "manager", "admin"]


class Faker:
    """Deterministic fake values derived from a secret and a seed."""

    def __init__(self, secret: bytes, seed: str, profile: dict, today: date | None = None):
        self.secret = secret
        self.seed = seed
        self.profile = profile
        self.today = today or date.today()

    def _bytes(self, label: str, size: int = 32) -> bytes:
        out = b""
        counter = 0
        while len(out) < size:
            message = f"{self.seed}|{label}|{counter}".encode("utf-8")
            out += hmac.new(self.secret, message, hashlib.sha256).digest()
            counter += 1
        return out[:size]

    def number(self, label: str, low: int, high: int) -> int:
        if high < low:
            low, high = high, low
        value = int.from_bytes(self._bytes(label, 8), "big")
        return low + value % (high - low + 1)

    def password(self, label: str) -> str:
        alphabet = string.ascii_letters + string.digits
        raw = self._bytes("pw:" + label, 16)
        body = "".join(alphabet[b % len(alphabet)] for b in raw[:10])
        symbol = "!@#$%&*"[raw[10] % 7]
        return body[:4].capitalize() + body[4:] + symbol + str(raw[11] % 90 + 10)

    def hexstr(self, label: str, length: int) -> str:
        return self._bytes("hex:" + label, (length + 1) // 2).hex()[:length]

    def token(self, label: str) -> str:
        return "sk_live_" + self.hexstr("tok:" + label, 32)

    def ip(self, label: str) -> str:
        prefix = str(self.profile.get("internal_subnet") or "10.20.0")
        parts = prefix.split(".")[:3]
        while len(parts) < 3:
            parts.append("0")
        return ".".join(parts + [str(self.number("ip:" + label, 10, 240))])

    def day(self, offset: int = 0) -> str:
        return (self.today + timedelta(days=offset)).isoformat()

    def person(self, index: int) -> dict:
        label = f"person:{index}"
        first = FIRST_NAMES[self.number(label + ":f", 0, len(FIRST_NAMES) - 1)]
        last = LAST_NAMES[self.number(label + ":l", 0, len(LAST_NAMES) - 1)]
        domain = str(self.profile.get("domain") or "example.local")
        username = (first[0] + last).lower()
        return {"id": 1000 + index, "name": f"{first} {last}", "username": username,
                "email": f"{username}@{domain}",
                "department": DEPARTMENTS[self.number(label + ":d", 0, len(DEPARTMENTS) - 1)],
                "role": ROLES[self.number(label + ":r", 0, len(ROLES) - 1)],
                "phone": "08" + str(self.number(label + ":p", 10000000, 99999999)),
                "last_login": self.day(-self.number(label + ":ll", 0, 30)) + "T0" +
                              str(self.number(label + ":h", 1, 9)) + ":" +
                              str(self.number(label + ":m", 10, 59)) + ":00Z"}

    def people(self, count: int) -> list[dict]:
        return [self.person(i) for i in range(max(0, min(count, 200)))]


def _lookup(profile: dict, dotted: str):
    value = profile
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            raise KeyError(dotted)
        value = value[part]
    return value


def render(template: str, faker: Faker, node_paths: dict, context: dict | None = None) -> str:
    """Replace every placeholder; unknown placeholders raise KeyError."""
    context = context or {}

    def replace(match: re.Match) -> str:
        expr = match.group(1)
        if expr.startswith("org."):
            return str(_lookup(faker.profile, expr[4:]))
        if expr.startswith("ctx."):
            return str(_lookup(context, expr[4:]))
        if expr.startswith("node:"):
            return node_paths[expr[5:]]
        if expr == "date":
            return faker.day(0)
        if expr.startswith("date:"):
            return faker.day(int(expr[5:]))
        if expr.startswith("ip:"):
            return faker.ip(expr[3:])
        if expr.startswith("secret:"):
            parts = expr.split(":")
            kind = parts[1] if len(parts) > 1 else ""
            if kind == "password" and len(parts) == 3:
                return faker.password(parts[2])
            if kind == "hex" and len(parts) == 4:
                return faker.hexstr(parts[3], int(parts[2]))
            if kind == "token" and len(parts) == 3:
                return faker.token(parts[2])
            if kind == "int" and len(parts) == 5:
                return str(faker.number(parts[4], int(parts[2]), int(parts[3])))
            raise KeyError(expr)
        if expr.startswith("person:"):
            _, index, field = expr.split(":")
            return str(faker.person(int(index))[field])
        if expr.startswith("people_csv:"):
            rows = faker.people(int(expr.split(":")[1]))
            header = "id,name,email,department,role,phone,last_login"
            lines = [",".join(str(r[k]) for k in ("id", "name", "email", "department",
                                                  "role", "phone", "last_login")) for r in rows]
            return "\n".join([header] + lines)
        if expr.startswith("people_json:"):
            return json.dumps(faker.people(int(expr.split(":")[1])), indent=2)
        raise KeyError(expr)

    return PLACEHOLDER.sub(replace, template)


def placeholders(template: str) -> list[str]:
    return [m.group(1) for m in PLACEHOLDER.finditer(template)]
