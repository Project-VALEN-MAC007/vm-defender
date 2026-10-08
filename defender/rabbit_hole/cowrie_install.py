"""Install the Rabbit Hole decoy files into a Cowrie honeypot.

Cowrie keeps its fake filesystem in fs.pickle (names, sizes, owners) and serves
file contents from the honeyfs/ folder for every pickle entry that has a file
there. This module writes both, so the decoys the Dashboard configures appear in
Cowrie without running fsctl by hand.

It is idempotent: a manifest of what it installed lets the next run replace or
remove old decoys when the scenario changes, and nothing is touched when the
scenario is unchanged. fs.pickle is backed up before every change.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pickle
import posixpath
import shlex
import shutil
import subprocess
import time

from .shell import render_files

# Field and type numbers of a Cowrie filesystem node (cowrie/shell/fs.py).
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2
DIR_MODE, FILE_MODE = 0o40755, 0o100644


def _signature(files: dict) -> str:
    return hashlib.sha256(json.dumps(sorted(files.items()), ensure_ascii=False).encode("utf-8")).hexdigest()


def _child(node: list, name: str):
    for item in node[A_CONTENTS]:
        if item[A_NAME] == name:
            return item
    return None


def _lookup(root: list, path: str):
    node = root
    for part in [p for p in path.split("/") if p]:
        if node[A_TYPE] != T_DIR:
            return None
        node = _child(node, part)
        if node is None:
            return None
    return node


def _ensure_dir(root: list, path: str, owner: int, created: list) -> list:
    node, current = root, ""
    for part in [p for p in path.split("/") if p]:
        current += "/" + part
        found = _child(node, part)
        if found is None:
            found = [part, T_DIR, owner, owner, 4096, DIR_MODE, time.time(), [], None, None]
            node[A_CONTENTS].append(found)
            created.append(current)
        elif found[A_TYPE] != T_DIR:
            raise ValueError(f"{current} exists in Cowrie and is not a directory")
        node = found
    return node


def _remove(root: list, path: str) -> None:
    parent = _lookup(root, posixpath.dirname(path))
    if parent is None or parent[A_TYPE] != T_DIR:
        return
    parent[A_CONTENTS] = [item for item in parent[A_CONTENTS] if item[A_NAME] != posixpath.basename(path)]


def install(config, fs_pickle: Path, honeyfs: Path, state_dir: Path, force: bool = False) -> dict:
    # Turning Rabbit Hole off in the Dashboard takes the decoys out of Cowrie too.
    files = render_files(config) if config.enabled else {}
    signature = _signature(files)
    manifest_path = state_dir / "cowrie-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = {"signature": None, "files": [], "dirs": []}
    if manifest.get("signature") == signature and not force:
        return {"changed": False, "files": len(manifest.get("files", []))}

    state_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    shutil.copy2(fs_pickle, state_dir / f"fs.pickle.{stamp}.bak")
    with fs_pickle.open("rb") as stream:
        root = pickle.load(stream)  # Cowrie's own file on this machine, not network input.

    # Take out what the previous run added before adding the new decoys.
    for path in manifest.get("files", []):
        _remove(root, path)
        (honeyfs / path.lstrip("/")).unlink(missing_ok=True)
    for path in sorted(manifest.get("dirs", []), key=len, reverse=True):
        node = _lookup(root, path)
        if node is not None and node[A_TYPE] == T_DIR and not node[A_CONTENTS]:
            _remove(root, path)

    home = "/home/" + config.organization["admin_user"]
    created_dirs: list = []
    installed: list = []
    for path, (kind, content) in sorted(files.items()):
        owner = 1000 if path == home or path.startswith(home + "/") else 0
        if kind == "dir":
            _ensure_dir(root, path, owner, created_dirs)
            continue
        parent = _ensure_dir(root, posixpath.dirname(path), owner, created_dirs)
        data = content.encode("utf-8")
        name = posixpath.basename(path)
        parent[A_CONTENTS] = [item for item in parent[A_CONTENTS] if item[A_NAME] != name]
        parent[A_CONTENTS].append([name, T_FILE, owner, owner, len(data), FILE_MODE, time.time(), [], None, None])
        target = honeyfs / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        os.chmod(target, 0o644)
        installed.append(path)

    temporary = fs_pickle.with_name("." + fs_pickle.name + ".tmp")
    with temporary.open("wb") as stream:
        pickle.dump(root, stream)
    os.replace(temporary, fs_pickle)
    kept = [path for path in manifest.get("dirs", []) if _lookup(root, path) is not None]
    manifest = {"signature": signature, "files": installed,
                "dirs": sorted(set(kept) | set(created_dirs)), "installed_at": stamp}
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"changed": True, "files": len(installed), "dirs_created": len(created_dirs)}


def restart(command: str) -> bool:
    """Cowrie reads fs.pickle only at start."""
    if not command:
        return True
    return subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=120).returncode == 0
