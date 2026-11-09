"""Stage 2: LOCAL, NON-PRIVILEGED device and access lifecycle.

Adapted from the user's CTF WireGuard broker: SQLite device registry, IP
allocation, membership-change revocation and retired-key tracking.

IMPORTANT: no WireGuard or nftables commands are executed by this module.
The local roster is a TRUSTED ADMIN DEMO input, not user authentication.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import os
import re
import sqlite3
import time
import uuid
from pathlib import Path

from .roster import load_roster

IP_POOL = ipaddress.ip_network("10.77.0.0/24")
IP_LAST_OCTETS = range(100, 255)
MAX_DEVICES_PER_USER = 2
KEY_PATTERN = re.compile(r"[A-Za-z0-9+/]{43}=")
DEVICE_ID_PATTERN = re.compile(r"[a-f0-9]{32}")


def validate_public_key(public_key: str) -> bool:
    if not isinstance(public_key, str) or not KEY_PATTERN.fullmatch(public_key):
        return False
    try:
        raw = base64.b64decode(public_key, validate=True)
        return len(raw) == 32 and base64.b64encode(raw).decode("ascii") == public_key
    except (binascii.Error, ValueError):
        return False


def open_db(path: str | Path) -> sqlite3.Connection:
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # State belongs on Kali's Linux filesystem, NOT the Windows shared mount.
    old_umask = os.umask(0o077)
    try:
        conn = sqlite3.connect(path, timeout=5)
    finally:
        os.umask(old_umask)
    path.chmod(0o600)
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("""CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        group_id INTEGER NOT NULL,
        ip TEXT NOT NULL UNIQUE,
        public_key TEXT NOT NULL UNIQUE,
        label TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS retired_keys (
        public_key TEXT PRIMARY KEY
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS devices_user ON devices(user_id)")
    conn.commit()
    return conn


def allocate_ip(conn: sqlite3.Connection) -> str:
    """Reserve from our demo pool. Live gateway overlap checks come in Stage 4."""
    assigned = {row[0] for row in conn.execute("SELECT ip FROM devices")}
    for last_octet in IP_LAST_OCTETS:
        ip = f"10.77.0.{last_octet}/32"
        if ip not in assigned:
            return ip
    raise RuntimeError("No free VPN IP addresses")


def register_device(
    db_path: str | Path, roster_path: str | Path, user_id: int,
    label: str, public_key: str,
) -> dict:
    """Register an ALREADY client-generated public key; never handle private keys."""
    if type(user_id) is not int or user_id <= 0:
        raise ValueError("user_id must be a positive integer")
    if not isinstance(label, str) or not 1 <= len(label) <= 32 or any(ord(c) < 32 for c in label):
        raise ValueError("Invalid device label (1-32 printable characters)")
    if not validate_public_key(public_key):
        raise ValueError("Invalid WireGuard public key")
    # A local admin controls this file. Do NOT expose user_id as unauthenticated API input.
    roster = load_roster(roster_path)
    group_id = roster.get(user_id)
    if group_id is None:
        raise PermissionError("User is not in the trusted roster")
    conn = open_db(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT 1 FROM retired_keys WHERE public_key=?", (public_key,)).fetchone():
            raise ValueError("Retired public key cannot be re-registered")
        if conn.execute("SELECT 1 FROM devices WHERE public_key=?", (public_key,)).fetchone():
            raise ValueError("Public key is already registered")
        count = conn.execute("SELECT COUNT(*) FROM devices WHERE user_id=?", (user_id,)).fetchone()[0]
        if count >= MAX_DEVICES_PER_USER:
            raise ValueError("Device limit reached (2 devices per user)")
        result = {
            "device_id": uuid.uuid4().hex,
            "user_id": user_id,
            "group_id": group_id,
            "ip": allocate_ip(conn),
            "label": label,
        }
        conn.execute(
            "INSERT INTO devices (device_id,user_id,group_id,ip,public_key,label,created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (result["device_id"], user_id, group_id, result["ip"], public_key, label, int(time.time())),
        )
        conn.commit()
        return result
    finally:
        conn.close()


def list_devices(db_path: str | Path) -> list[dict]:
    conn = open_db(db_path)
    try:
        rows = conn.execute(
            "SELECT device_id,user_id,group_id,ip,label FROM devices ORDER BY user_id,created_at,device_id"
        )
        return [dict(zip(("device_id", "user_id", "group_id", "ip", "label"), r)) for r in rows]
    finally:
        conn.close()


def revoke_device(db_path: str | Path, device_id: str) -> dict:
    """Trusted local admin operation; Stage 4 will remove the live WG peer."""
    if not isinstance(device_id, str) or not DEVICE_ID_PATTERN.fullmatch(device_id):
        raise ValueError("Invalid device ID")
    conn = open_db(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT public_key FROM devices WHERE device_id=?", (device_id,)).fetchone()
        if row is None:
            raise ValueError("Device not found")
        conn.execute("INSERT OR IGNORE INTO retired_keys VALUES (?)", (row[0],))
        conn.execute("DELETE FROM devices WHERE device_id=?", (device_id,))
        conn.commit()
        return {"revoked": device_id}
    finally:
        conn.close()


def reconcile_local(db_path: str | Path, roster_path: str | Path) -> dict:
    """Revoke stale database memberships; NOT live network access yet."""
    roster = load_roster(roster_path)  # Validate fully before any DB mutation
    conn = open_db(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        invalid = [
            (did, pub)
            for did, uid, group, pub in conn.execute(
                "SELECT device_id,user_id,group_id,public_key FROM devices"
            ) if roster.get(uid) != group
        ]
        for device_id, public_key in invalid:
            conn.execute("INSERT OR IGNORE INTO retired_keys VALUES (?)", (public_key,))
            conn.execute("DELETE FROM devices WHERE device_id=?", (device_id,))
        remaining = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        conn.commit()
        return {"removed_from_local_registry": len(invalid), "active_local_devices": remaining}
    finally:
        conn.close()


def desired_access_by_group(db_path: str | Path) -> dict[str, list[str]]:
    """Desired firewall membership snapshot; NO nftables modifications yet."""
    conn = open_db(db_path)
    try:
        result: dict[str, list[str]] = {}
        for group_id, ip in conn.execute("SELECT group_id,ip FROM devices ORDER BY group_id,ip"):
            result.setdefault(str(group_id), []).append(ip)
        return result
    finally:
        conn.close()
