"""Shell side of Rabbit Hole (SSH/Telnet through Cowrie).

Two jobs:

1. ``export_bundle`` renders the chosen shell scenario into files for Cowrie:
   ``honeyfs/...`` holds file contents and ``fsctl-commands.txt`` adds the
   matching entries to Cowrie's filesystem pickle.
2. ``events_from_cowrie`` reads Cowrie JSON events and turns commands that
   touch decoy paths into Rabbit Hole events. Typing ``cat file`` is evidence
   of an attempt only; Cowrie's own output decides whether the file was shown.
"""
from __future__ import annotations

import io
import posixpath
import re
import shlex
import zipfile

from .config import RabbitConfig
from .render import Faker, render

READ_COMMANDS = {"cat", "less", "more", "head", "tail", "vi", "vim", "nano", "strings",
                 "grep", "cp", "scp", "base64", "file", "source", "."}
LIST_COMMANDS = {"ls", "ll", "dir", "find", "tree", "stat"}
SPLIT = re.compile(r"\|\||&&|[;|]")


def shell_scenario(config: RabbitConfig):
    chosen = config.selected("shell")
    return chosen[0] if chosen else None


def render_files(config: RabbitConfig) -> dict:
    """Map absolute path -> (kind, content). Shell content uses the deployment seed
    because Cowrie serves the same filesystem to every session."""
    scenario = shell_scenario(config)
    if scenario is None:
        return {}
    faker = Faker(config.secret(), "shell", config.organization, config.anchor_date())
    paths = scenario.node_paths()
    files = {}
    for node in scenario.nodes.values():
        content = "" if node.kind == "dir" else render(node.body, faker, paths)
        files[node.path] = (node.kind, content)
    return files


def export_bundle(config: RabbitConfig) -> bytes:
    """Zip with honeyfs contents, fsctl commands and install notes."""
    files = render_files(config)
    directories = set()
    commands = []
    for path, (kind, _) in sorted(files.items()):
        parent = posixpath.dirname(path) if kind == "file" else path
        chain = []
        while parent and parent != "/":
            chain.append(parent)
            parent = posixpath.dirname(parent)
        for directory in reversed(chain):
            if directory not in directories:
                directories.add(directory)
                commands.append(f"mkdir {directory}")
    for path, (kind, content) in sorted(files.items()):
        if kind == "file":
            commands.append(f"touch {path} {len(content.encode('utf-8'))}")
    owner = config.organization["admin_user"]
    commands.append(f"chown 1000 /home/{owner}")
    readme = "\n".join([
        "TRAP Rabbit Hole - Cowrie bundle",
        "",
        "1. Stop Cowrie.",
        "2. Back up honeyfs/ and the filesystem pickle (fs.pickle).",
        "3. Copy the honeyfs/ folder of this bundle over Cowrie's honeyfs/ (merge).",
        "4. Apply the filesystem entries:",
        "     fsctl <path-to>/fs.pickle < fsctl-commands.txt",
        "   (check the fsctl location and syntax for the installed Cowrie version)",
        f"5. Start Cowrie, log in as a test client and run: ls -la /home/{owner}",
        "",
        "Every value in these files is generated for the decoy only.",
    ])
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", readme + "\n")
        archive.writestr("fsctl-commands.txt", "\n".join(commands) + "\n")
        for path, (kind, content) in sorted(files.items()):
            if kind == "file":
                archive.writestr("honeyfs" + path, content)
    return buffer.getvalue()


def _tokens(segment: str) -> list:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def _resolve(token: str, cwd: str, home: str) -> str:
    if token == "~" or token.startswith("~/"):
        token = home + token[1:]
    if not token.startswith("/"):
        token = posixpath.join(cwd, token)
    normal = posixpath.normpath(token)
    return "/" if normal in {"", "."} else normal


def events_from_cowrie(events: list, config: RabbitConfig) -> list:
    """Convert Cowrie events (oldest first or any order) into Rabbit Hole events."""
    scenario = shell_scenario(config)
    if scenario is None:
        return []
    by_path = scenario.by_path()
    children = {}
    for node in scenario.nodes.values():
        children.setdefault(posixpath.dirname(node.path), []).append(node.id)
    sessions = {}
    output = []
    for event in sorted(events, key=lambda e: str(e.get("timestamp") or "")):
        eventid = str(event.get("eventid") or "")
        sid = event.get("session") or event.get("session_id")
        if not eventid.startswith("cowrie.") or not sid:
            continue
        state = sessions.setdefault(sid, {"protocol": "ssh", "home": "/root", "cwd": "/root",
                                          "revealed": {}, "accessed": set()})
        if eventid == "cowrie.session.connect" and event.get("protocol"):
            state["protocol"] = str(event["protocol"]).lower()
        if eventid == "cowrie.login.success":
            user = str(event.get("username") or "root")
            state["home"] = "/root" if user == "root" else "/home/" + user
            state["cwd"] = state["home"]
        if eventid == "cowrie.session.closed":
            output.append(_shell_event(event, state, "session_closed", None, None, scenario))
            continue
        if eventid != "cowrie.command.input":
            continue
        command = str(event.get("input") or "")
        for segment in SPLIT.split(command):
            words = _tokens(segment.strip())
            while words and words[0] in {"sudo", "busybox", "command"}:
                words = words[1:]
            if not words:
                continue
            verb = posixpath.basename(words[0])
            args = [w for w in words[1:] if not w.startswith("-")]
            if verb == "cd":
                state["cwd"] = _resolve(args[0] if args else "~", state["cwd"], state["home"])
                target = by_path.get(state["cwd"])
                if target is not None:
                    output.append(_shell_event(event, state, "change_directory", target, command, scenario))
                continue
            if verb in LIST_COMMANDS and not args:
                args = ["."]
            if verb not in READ_COMMANDS and verb not in LIST_COMMANDS:
                continue
            for arg in args:
                path = _resolve(arg, state["cwd"], state["home"])
                node = by_path.get(path)
                if node is not None:
                    action = "list_attempt" if node.kind == "dir" or verb in LIST_COMMANDS else "read_attempt"
                    output.append(_shell_event(event, state, action, node, command, scenario))
                elif verb in LIST_COMMANDS and path in children:
                    # Listing a parent folder shows decoy names; it is a clue, not an access.
                    for child in children[path]:
                        state["revealed"].setdefault(child, "listing:" + path)
    return output


def _shell_event(event, state, action, node, command, scenario) -> dict:
    item = {
        "timestamp": event.get("timestamp"), "event": "rabbit_hole.shell", "profile": "cowrie",
        "protocol": state["protocol"], "session_id": str(event.get("session") or event.get("session_id")),
        "link": "cowrie_session", "source_ip": event.get("src_ip"), "source_port": event.get("src_port"),
        "action": action, "command": (command or "")[:512], "scenario": scenario.id,
        "node_id": None, "resource_id": None, "kind": None, "depth": None,
        "clue_from": None, "followed_clue": False, "limit_reached": False,
        "evidence": "command_typed",
    }
    if action == "session_closed":
        item["connection_seconds"] = event.get("duration")
        return item
    item.update(node_id=node.id, resource_id=node.id, kind=node.kind, depth=node.depth)
    if node.id in state["revealed"]:
        item["clue_from"] = state["revealed"][node.id]
        # Seeing a name in a folder listing is not following a decoy clue.
        item["followed_clue"] = not item["clue_from"].startswith("listing:")
    for child in node.next:
        state["revealed"].setdefault(child, node.id)
    state["accessed"].add(node.id)
    return item
