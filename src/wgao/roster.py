"""Local identity provider for DEVELOPMENT ONLY (no user-facing authentication)."""
from __future__ import annotations

import json
from pathlib import Path

def load_roster(path: str | Path) -> dict[int, int]:
    """Read local users/groups; require positive integer identities.

    Fail closed on a malformed identity roster. The caller is a trusted local
    developer/admin, NOT an anonymous network client.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("members"), list):
        raise ValueError("Expected {'members': [...]} in local roster")
    roster: dict[int, int] = {}
    for m in data["members"]:
        if not isinstance(m, dict):
            raise ValueError("Malformed roster entry")
        uid, gid = m.get("user_id"), m.get("group_id")
        if type(uid) is not int or uid <= 0:
            raise ValueError("user_id must be a positive integer")
        if type(gid) is not int or not 1 <= gid <= 254:
            raise ValueError("group_id must be an integer from 1 to 254")
        if uid in roster:
            raise ValueError("Duplicate user_id")
        roster[uid] = gid
    return roster
