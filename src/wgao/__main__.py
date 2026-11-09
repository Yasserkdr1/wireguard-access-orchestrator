"""Stage 2 CLI - local simulation only, never executes wg/nft/sudo."""
import argparse
import json
from pathlib import Path
from .roster import load_roster
from .broker import (
    register_device, list_devices, revoke_device, reconcile_local, desired_access_by_group,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="WireGuard Access Orchestrator (local Stage 2)")
    parser.add_argument("--roster", default="config/roster.example.json")
    parser.add_argument("--db", default=str(Path.home() / ".local/state/wgao/peers.sqlite3"))
    sub = parser.add_subparsers(dest="action")
    sub.add_parser("users", help="Show trusted demo roster")
    reg = sub.add_parser("register", help="Register client-generated WG public key (offline)")
    reg.add_argument("--user-id", required=True, type=int)
    reg.add_argument("--label", required=True)
    reg.add_argument("--public-key", required=True)
    sub.add_parser("devices", help="Show local registered devices")
    rev = sub.add_parser("revoke", help="Revoke a local device record")
    rev.add_argument("--device-id", required=True)
    sub.add_parser("reconcile", help="Revoke records that no longer match roster")
    sub.add_parser("policy", help="View desired access IPs by group (no nft changes)")
    args = parser.parse_args()
    try:
        if args.action in (None, "users"):
            roster = load_roster(args.roster)
            result = {"trusted_local_users": roster}
        elif args.action == "register":
            result = register_device(args.db, args.roster, args.user_id, args.label, args.public_key)
        elif args.action == "devices":
            result = {"devices": list_devices(args.db)}
        elif args.action == "revoke":
            result = revoke_device(args.db, args.device_id)
        elif args.action == "reconcile":
            result = reconcile_local(args.db, args.roster)
        elif args.action == "policy":
            result = {"desired_access_by_group": desired_access_by_group(args.db)}
        else:
            parser.error("Unknown action")
        print(json.dumps(result, indent=2, sort_keys=True))
        print("LOCAL ONLY: no WireGuard peers or nftables rules changed.")
    except (ValueError, PermissionError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    main()
