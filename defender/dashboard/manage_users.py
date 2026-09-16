from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path

from .security import ALLOWED_ROLES, hash_password


def upsert_user(path: Path, username: str, name: str, role: str, password: str) -> None:
    if role not in ALLOWED_ROLES:
        raise ValueError(f"role must be one of {sorted(ALLOWED_ROLES)}")
    payload = {"users": []}
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
    users = [item for item in payload.get("users", []) if item.get("username") != username]
    users.append({
        "username": username,
        "name": name,
        "role": role,
        "password_hash": hash_password(password),
        "disabled": False,
    })
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps({"users": users}, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or update a MIMIC dashboard user")
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument("--username", required=True)
    parser.add_argument("--name")
    parser.add_argument("--role", choices=sorted(ALLOWED_ROLES), required=True)
    parser.add_argument("--password-env", help="read the password from this environment variable")
    args = parser.parse_args()
    password = os.environ.get(args.password_env, "") if args.password_env else getpass.getpass("Password: ")
    if not password:
        parser.error("password is required")
    upsert_user(args.file, args.username, args.name or args.username, args.role, password)
    print(f"updated {args.username} in {args.file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
