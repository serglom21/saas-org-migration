"""Remember org slugs and tokens until the terminal that entered them is closed.

Each terminal runs its shell as a session leader, so the file is named after the
session id. Once that shell exits, the file is never read again, and the next run
from any terminal deletes it.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path

from org_copy.files import write_json


def remembered(prefix: str) -> tuple[str, str] | None:
    """Return the org slug and token saved for prefix in this terminal, if any."""
    entry = _read().get(prefix)
    if isinstance(entry, dict) and entry.get("org") and entry.get("token"):
        return entry["org"], entry["token"]
    return None


def remember(prefix: str, org: str, token: str) -> None:
    path = _path()
    if path is None:
        return
    data = _read()
    data["tty"] = _terminal()
    data[prefix] = {"org": org, "token": token}
    write_json(str(path), data, secret=True)


def masked(token: str) -> str:
    return f"{token[:4]}...{token[-4:]}" if len(token) >= 16 else "..."


def _read() -> dict:
    path = _path()
    if path is None:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get("tty") != _terminal():
        # The session id was reused by another terminal.
        path.unlink(missing_ok=True)
        return {}
    return data


def _path() -> Path | None:
    """The file for this terminal, or None when there is no terminal or no private directory."""
    session = _session()
    if session is None or _terminal() is None:
        return None
    directory = _directory()
    try:
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
    except OSError:
        return None
    # Never write tokens into a directory that someone else owns or can read.
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        return None
    _remove_closed(directory, session)
    return directory / f"{session}.json"


def _remove_closed(directory: Path, current: int) -> None:
    for path in directory.glob("*.json"):
        if path.stem.isdigit() and int(path.stem) != current and not _running(int(path.stem)):
            path.unlink(missing_ok=True)


def _running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Another user's process took the id, so our terminal is gone.
        return False
    return True


def _session() -> int | None:
    try:
        return os.getsid(0)
    except (AttributeError, OSError):
        return None


def _terminal() -> str | None:
    try:
        return os.ttyname(sys.stdin.fileno())
    except (AttributeError, OSError, ValueError):
        return None


def _directory() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    return Path(base) / f"org-copy-{os.getuid()}"
