from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time
import tempfile


PBKDF2_ITERATIONS = 600_000
ALLOWED_ROLES = {"master_admin", "user"}


def totp_code(secret: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret.upper(), casefold=True)
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
    return str(value % (10 ** digits)).zfill(digits)


def match_totp(secret: str, code: str, last_counter: int = -1) -> int | None:
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
        return None
    counter = int(time.time()) // 30
    try:
        for candidate in (counter, counter - 1, counter + 1):
            if candidate > last_counter and hmac.compare_digest(totp_code(secret, candidate), code):
                return candidate
    except (ValueError, TypeError):
        pass
    return None


PASSWORD_SPECIALS = "!@#$%^&*()-_=+[]{};:,.<>/?~"


def password_problem(password) -> str | None:
    """Password policy for every password a person chooses: 12-128 characters with
    lowercase, uppercase and a special character. Returns None when it passes."""
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        return "length"
    if not re.search(r"[a-z]", password):
        return "lowercase"
    if not re.search(r"[A-Z]", password):
        return "uppercase"
    if not any(not ch.isalnum() and not ch.isspace() for ch in password):
        return "special"
    return None


def generate_password(length: int = 20) -> str:
    """Random password that always satisfies password_problem()."""
    rng = secrets.SystemRandom()
    pools = ["abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#%^*-_=+?"]
    chars = [rng.choice(pool) for pool in pools]
    everything = "".join(pools)
    chars += [rng.choice(everything) for _ in range(length - len(chars))]
    rng.shuffle(chars)
    return "".join(chars)


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    if len(password) < 12:
        raise ValueError("password must contain at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            base64.urlsafe_b64decode(salt.encode("ascii")),
            int(iterations),
        )
        return hmac.compare_digest(
            base64.urlsafe_b64encode(digest).decode("ascii"), expected
        )
    except (TypeError, ValueError):
        return False


class UserStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._pending_totp = {}
        self._login_challenges = {}

    def begin_login(self, username: str, password: str, require_totp: bool = True) -> dict | None:
        with self._lock:
            account = self.load().get(username)
            if not account or account["disabled"] or not verify_password(password, account["password_hash"]):
                return None
            if not require_totp:
                return {**{key: account[key] for key in ("username", "name", "role")},
                        "totp_enabled": bool(account["totp_secret"])}
            now = time.monotonic()
            self._login_challenges = {key: value for key, value in self._login_challenges.items()
                                      if value["expiry"] > now}
            token = secrets.token_urlsafe(32)
            self._login_challenges[token] = {
                "username": username, "password_hash": account["password_hash"],
                "original_secret": account["totp_secret"],
                "secret": account["totp_secret"] or base64.b32encode(secrets.token_bytes(20)).decode("ascii"),
                "expiry": now + 300, "attempts": 0}
            result = {"totp_required": True, "challenge": token}
            if not account["totp_secret"]:
                result["enrollment_secret"] = self._login_challenges[token]["secret"]
            return result

    def complete_login(self, token: str, code: str) -> dict | None:
        with self._lock:
            challenge = self._login_challenges.get(token) if isinstance(token, str) else None
            if not challenge:
                return None
            users = self.load()
            account = users.get(challenge["username"])
            if (challenge["expiry"] <= time.monotonic() or challenge["attempts"] >= 5
                    or not account or account["disabled"]
                    or account["password_hash"] != challenge["password_hash"]
                    or account["totp_secret"] != challenge["original_secret"]):
                self._login_challenges.pop(token, None)
                return None
            challenge["attempts"] += 1
            counter = match_totp(challenge["secret"], code, account["totp_last_counter"])
            if counter is None:
                return None
            account["totp_secret"] = challenge["secret"]
            account["totp_last_counter"] = counter
            self._save(users)
            self._login_challenges.pop(token, None)
            return {**{key: account[key] for key in ("username", "name", "role")}, "totp_enabled": True}

    def load(self) -> dict[str, dict]:
        if not self.path.is_file():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        users = {}
        for item in raw.get("users", []):
            username = str(item.get("username", "")).strip()
            role = str(item.get("role", ""))
            password_hash = str(item.get("password_hash", ""))
            if username and role in ALLOWED_ROLES and password_hash:
                users[username] = {
                    "username": username,
                    "name": str(item.get("name") or username),
                    "role": role,
                    "password_hash": password_hash,
                    "disabled": bool(item.get("disabled", False)),
                    "totp_secret": item.get("totp_secret", ""),
                    "totp_last_counter": int(item.get("totp_last_counter", -1)),
                    "must_change_password": bool(item.get("must_change_password", False)),
                }
        return users

    def authenticate(self, username: str, password: str, code: str = "") -> dict | None:
        with self._lock:
            users = self.load()
            account = users.get(username)
            if not account or account["disabled"] or not verify_password(password, account["password_hash"]):
                return None
            if account["totp_secret"]:
                counter = match_totp(account["totp_secret"], code, account["totp_last_counter"])
                if counter is None:
                    return None
                account["totp_last_counter"] = counter
                self._save(users)
            else:
                return None
            return {**{key: account[key] for key in ("username", "name", "role")},
                    "totp_enabled": bool(account["totp_secret"])}

    def setup_totp(self, username: str, password: str, code: str | None = None) -> str | None:
        with self._lock:
            users = self.load()
            account = users.get(username)
            if not account or account["disabled"] or not verify_password(password, account["password_hash"]):
                raise ValueError("invalid_current_password")
            if account["totp_secret"]:
                raise ValueError("totp_already_enabled")
            if code is None:
                secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
                self._pending_totp[username] = (secret, time.monotonic() + 300, 0)
                return secret
            secret, expiry, attempts = self._pending_totp.get(username, ("", 0, 0))
            if time.monotonic() > expiry or attempts >= 5:
                self._pending_totp.pop(username, None)
                raise ValueError("totp_setup_expired")
            counter = match_totp(secret, code)
            if counter is None:
                self._pending_totp[username] = (secret, expiry, attempts + 1)
                raise ValueError("invalid_totp")
            account["totp_secret"] = secret
            account["totp_last_counter"] = counter
            self._save(users)
            self._pending_totp.pop(username, None)
            return None

    def list_public(self) -> list[dict]:
        return [self._public(account) for account in sorted(self.load().values(), key=lambda a: a["username"])]

    @staticmethod
    def _public(account: dict) -> dict:
        return {**{key: account[key] for key in ("username", "name", "role", "disabled")},
                "totp_enabled": bool(account.get("totp_secret"))}

    def create_user(self, username: str, name: str, password: str | None = None) -> tuple[dict, str | None]:
        username, name = username.strip(), name.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,31}", username):
            raise ValueError("invalid_username")
        if not name or len(name) > 100 or any(ord(c) < 32 for c in name):
            raise ValueError("invalid_name")
        if password is not None and password_problem(password):
            raise ValueError("invalid_password")
        with self._lock:
            users = self.load()
            if username in users:
                raise ValueError("username_exists")
            issued_password = generate_password() if password is None else None
            account = {"username": username, "name": name, "role": "user",
                       "password_hash": hash_password(password if password is not None else issued_password),
                       "disabled": False}
            users[username] = account
            self._save(users)
            return self._public(account), issued_password

    def set_disabled(self, username: str, disabled: bool) -> dict:
        with self._lock:
            users = self.load()
            account = users.get(username)
            if not account or account["role"] != "user":
                raise ValueError("user_not_found")
            account["disabled"] = disabled
            self._save(users)
            return self._public(account)

    def reset_password(self, username: str) -> str:
        with self._lock:
            users = self.load()
            account = users.get(username)
            if not account or account["role"] != "user":
                raise ValueError("user_not_found")
            password = generate_password()
            account["password_hash"] = hash_password(password)
            self._save(users)
            return password

    def change_password(self, username: str, current: str, new: str) -> None:
        with self._lock:
            users = self.load()
            account = users.get(username)
            if not account or not verify_password(current, account["password_hash"]):
                raise ValueError("invalid_current_password")
            if current == new:
                raise ValueError("password_unchanged")
            if password_problem(new):
                raise ValueError("weak_password")
            account["password_hash"] = hash_password(new)
            account["must_change_password"] = False
            self._save(users)

    def verify_totp_action(self, username: str, code: str) -> bool:
        with self._lock:
            users = self.load()
            account = users.get(username)
            if not account or account["disabled"] or not account["totp_secret"]:
                return False
            counter = match_totp(account["totp_secret"], code, account["totp_last_counter"])
            if counter is None:
                return False
            account["totp_last_counter"] = counter
            self._save(users)
            return True

    def edit_user(self, username: str, name: str, role: str, delete: bool = False) -> dict:
        with self._lock:
            users = self.load()
            account = users.get(username)
            if not account:
                raise ValueError("user_not_found")
            if role not in ALLOWED_ROLES or not isinstance(name, str) or not name.strip() or len(name) > 100:
                raise ValueError("invalid_user")
            if account["role"] == "master_admin" and (delete or role != "master_admin"):
                if sum(u["role"] == "master_admin" and not u["disabled"] for u in users.values()) <= 1:
                    raise ValueError("last_master_admin")
            if delete:
                del users[username]
            else:
                account.update(name=name.strip(), role=role)
            self._save(users)
            return self._public(account)

    def _save(self, users: dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.path.parent,
                                             prefix=".users-", suffix=".tmp", delete=False) as stream:
                temporary = Path(stream.name)
                json.dump({"users": list(users.values())}, stream, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.chmod(0o600)
            os.replace(temporary, self.path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


@dataclass
class Session:
    user: dict
    csrf_token: str
    expires_at: datetime


class SessionStore:
    def __init__(self, ttl_seconds: int):
        self.ttl = timedelta(seconds=ttl_seconds)
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, user: dict) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        session = Session(dict(user), secrets.token_urlsafe(24), self._now() + self.ttl)
        with self._lock:
            self._prune_locked()
            self._sessions[token] = session
        return token, session

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        with self._lock:
            self._prune_locked()
            session = self._sessions.get(token)
            if session:
                session.expires_at = self._now() + self.ttl
            return session

    def delete(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(token, None)

    def delete_user(self, username: str) -> None:
        with self._lock:
            self._sessions = {token: session for token, session in self._sessions.items()
                              if session.user["username"] != username}

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def _prune_locked(self) -> None:
        now = self._now()
        self._sessions = {
            token: session for token, session in self._sessions.items()
            if session.expires_at > now
        }


class LoginLimiter:
    def __init__(self, maximum: int, window_seconds: int):
        self.maximum = maximum
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            attempts = [value for value in self._attempts.get(key, []) if value >= cutoff]
            self._attempts[key] = attempts
            if len(attempts) < self.maximum:
                return True, 0
            return False, max(1, int(self.window_seconds - (now - attempts[0])))

    def failure(self, key: str) -> None:
        with self._lock:
            self._attempts.setdefault(key, []).append(time.monotonic())

    def success(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)


def append_security_audit(path: Path, event: str, remote_ip: str,
                          username: str | None = None, detail: dict | None = None) -> None:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "remote_ip": remote_ip,
        "username": username,
        "detail": detail or {},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, sort_keys=True) + "\n")
