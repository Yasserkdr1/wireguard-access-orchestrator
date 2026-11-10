
"""Live WireGuard + nftables reconciliation for isolated lab."""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time

from .broker import (
    IP_POOL, open_db, reconcile_local, validate_public_key
)
from .nft_policy import load_resources, render_policy
from .policy_integrity import signature, reference_from_policy, repair
from .roster import load_roster


NS_PATTERN = re.compile(r"wgao-gw-[0-9]{3,15}\Z")


def run(ns, *args, stdin=None):
    result = subprocess.run(
        ["ip", "netns", "exec", ns, *args],
        input=stdin,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout


def desired_state(db, roster_file, resources_file):
    roster = load_roster(roster_file)
    resources = load_resources(resources_file)

    groups = {g: set() for g in resources["groups"]}
    peers = {}

    conn = open_db(db)
    try:
        rows = conn.execute(
            "SELECT user_id, group_id, ip, public_key "
            "FROM devices"
        ).fetchall()
    finally:
        conn.close()

    for user_id, group_id, cidr, key in rows:
        if roster.get(user_id) != group_id:
            continue

        if str(group_id) not in groups:
            continue

        if not validate_public_key(key):
            raise ValueError("Invalid WireGuard public key")

        addr = ipaddress.ip_interface(cidr)

        if addr.network.prefixlen != 32 or addr.ip not in IP_POOL:
            raise ValueError("Invalid VPN address")

        if key in peers:
            raise ValueError("Duplicate WireGuard key")

        peers[key] = str(addr)
        groups[str(group_id)].add(str(addr.ip))

    return groups, peers, resources


def parse_set(output, group):
    data = json.loads(output)

    matches = [
        item["set"]
        for item in data["nftables"]
        if "set" in item
        and item["set"].get("name") == f"clients_g{group}"
    ]

    if len(matches) != 1:
        raise RuntimeError("Missing nftables set")

    elements = matches[0].get("elem", [])

    if not all(isinstance(ip, str) for ip in elements):
        raise RuntimeError("Unsupported nftables elements")

    return set(elements)


def live_state(ns, groups):
    current_sets = {}

    for group in groups:
        output = run(
            ns, "nft", "-j", "list", "set",
            "inet", "wgao_demo", f"clients_g{group}"
        )
        current_sets[group] = parse_set(output, group)

    current_peers = {}

    output = run(ns, "wg", "show", "wg0", "allowed-ips")

    for line in output.splitlines():
        parts = line.split(maxsplit=1)

        if len(parts) != 2:
            raise RuntimeError("Unexpected WireGuard output")

        current_peers[parts[0]] = parts[1]

    return current_sets, current_peers


def synchronize(ns, db, roster, resources, apply=False, expected_signature=None):
    if not NS_PATTERN.fullmatch(ns):
        raise ValueError("Only isolated wgao-gw namespaces allowed")

    output = subprocess.run(
        ["ip", "netns", "list"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    namespaces = {
        line.split()[0]
        for line in output.splitlines()
        if line.strip()
    }

    if ns not in namespaces:
        raise ValueError("Gateway namespace not found")

    wanted_sets, wanted_peers, config = desired_state(
        db, roster, resources
    )

    if (
        config["vpn_interface"] != "wg0"
        or config["resource_interface"] != "eth1"
    ):
        raise ValueError("Unexpected lab network interfaces")

    current_sets, current_peers = live_state(
        ns, wanted_sets
    )
    if expected_signature is not None:
        observed = signature(
            run(ns, "nft", "-j", "list", "table", "inet", "wgao_demo")
        )

        if observed != expected_signature:
            if not apply:
                raise RuntimeError("Firewall policy integrity violation")

            repair(ns, config, wanted_sets, run)

            verified = signature(
                run(ns, "nft", "-j", "list", "table", "inet", "wgao_demo")
            )

            if verified != expected_signature:
                raise RuntimeError("Firewall repair verification failed")

            print(
                "FIREWALL-REPAIRED: unauthorized nftables change reverted",
                flush=True
            )
            current_sets, current_peers = live_state(ns, wanted_sets)


    changed_groups = [
        group for group in wanted_sets
        if wanted_sets[group] != current_sets[group]
    ]

    remove_peers = sorted(
        set(current_peers) - set(wanted_peers)
    )

    update_peers = sorted(
        key for key, address in wanted_peers.items()
        if current_peers.get(key) != address
    )

    result = {
        "set_updates": changed_groups,
        "peers_remove": len(remove_peers),
        "peers_add_or_fix": len(update_peers),
    }

    if not apply:
        return result

    if os.geteuid() != 0:
        raise PermissionError("Live changes require root")

    # Atomic update of owned nftables sets
    if changed_groups:
        commands = []

        for group in changed_groups:
            commands.append(
                f"flush set inet wgao_demo clients_g{group}"
            )

            if wanted_sets[group]:
                ips = ", ".join(
                    sorted(
                        wanted_sets[group],
                        key=ipaddress.IPv4Address
                    )
                )

                commands.append(
                    f"add element inet wgao_demo "
                    f"clients_g{group} {{ {ips} }}"
                )

        run(
            ns, "nft", "-f", "-",
            stdin="\n".join(commands) + "\n"
        )

    # Remove unauthorized peers
    for key in remove_peers:
        run(ns, "wg", "set", "wg0", "peer", key, "remove")

    # Add missing peers or correct their AllowedIPs
    for key in update_peers:
        run(
            ns, "wg", "set", "wg0",
            "peer", key,
            "allowed-ips", wanted_peers[key]
        )

    # Finally retire stale registrations from SQLite
    reconcile_local(db, roster)

    return result


def emergency_lockdown(namespace: str) -> None:
    """Disable VPN on a verified lab-only namespace."""

    if not NS_PATTERN.fullmatch(namespace):
        raise ValueError("Not a WGAO lab namespace")

    output = subprocess.run(
        ["ip", "netns", "list"],
        text=True, capture_output=True, check=True
    ).stdout

    names = {
        line.split()[0]
        for line in output.splitlines()
        if line.strip()
    }

    if namespace not in names:
        raise ValueError("Lab namespace does not exist")

    subprocess.run(
        ["ip", "-n", namespace, "link",
         "set", "dev", "wg0", "down"],
        text=True, capture_output=True, check=True
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument(
        "--roster", default="config/roster.example.json"
    )
    parser.add_argument(
        "--resources", default="config/resources.example.json"
    )
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=float, default=0.5)

    args = parser.parse_args()

    if args.watch and not args.apply:
        parser.error("--watch requires --apply")

    if not 0.2 <= args.interval <= 30:
        parser.error("Invalid polling interval")

    try:
        expected_signature = (
            reference_from_policy(
                render_policy(args.db, args.roster, args.resources)
            )
            if args.apply else None
        )
        while True:
            result = synchronize(
                args.namespace,
                args.db,
                args.roster,
                args.resources,
                args.apply,
                expected_signature=expected_signature,
            )

            if not args.watch or any(result.values()):
                print(json.dumps(result), flush=True)

            if not args.watch:
                break

            time.sleep(args.interval)

    except Exception as exc:
        if args.apply:
            try:
                emergency_lockdown(args.namespace)
                print(
                    "FAIL-CLOSED: wg0 disabled inside lab namespace",
                    file=sys.stderr
                )
            except Exception as lockdown_error:
                print(
                    f"CRITICAL: lockdown FAILED: {lockdown_error}",
                    file=sys.stderr
                )

        parser.exit(
            2, f"ERROR: reconciliation stopped: {exc}\n"
        )


if __name__ == "__main__":
    main()
