"""Read and write local snapshot, state, and checklist files."""

from __future__ import annotations

import json
import os
from typing import Any


def read_json(path: str) -> Any:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: str, data: Any, *, secret: bool = False) -> None:
    payload = json.dumps(data, indent=2, sort_keys=False) + "\n"
    if secret:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.chmod(path, 0o600)
        return
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(payload)


def write_text(path: str, text: str, *, secret: bool = False) -> None:
    if secret:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(path, 0o600)
        return
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def empty_state() -> dict[str, Any]:
    return {
        "teams": {},
        "projects": {},
        "detectors": {},
        "workflows": {},
        "monitors": {},
        "dashboards": {},
        "queries": {},
        "exploreQueries": {},
        "views": {},
        "forwarders": {},
        "keys": {},
    }


def load_state(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        return empty_state()
    data = read_json(path)
    state = empty_state()
    if isinstance(data, dict):
        for key in state:
            if isinstance(data.get(key), dict):
                state[key] = {str(k): str(v) for k, v in data[key].items()}
    return state
