"""Detect and repair policy drift in WGAO's nftables table."""
import ipaddress
import json
import subprocess

from .broker import IP_POOL


def signature(raw):
    """Compare rule structure, ignoring handles and dynamic IPs."""
    objects = json.loads(raw).get("nftables")
    if not isinstance(objects, list):
        raise ValueError("Invalid nftables JSON")

    normalized = []
    for item in objects:
        if not isinstance(item, dict) or len(item) != 1:
            raise ValueError("Unexpected nftables object")

        kind, entry = next(iter(item.items()))
        if kind == "metainfo":
            continue

        if kind not in ("table", "set", "chain", "rule"):
            raise ValueError("Unknown nftables object")
        if not isinstance(entry, dict):
            raise ValueError("Malformed nftables object")

        name = (
            entry.get("name") if kind == "table"
            else entry.get("table")
        )
        if entry.get("family") != "inet" or name != "wgao_demo":
            raise ValueError("Unexpected nftables table")

        stable = {
            k: v for k, v in entry.items()
            if k not in ("handle", "elem")
        }
        normalized.append((kind, stable))

    if not any(k == "table" for k, _ in normalized):
        raise ValueError("Missing WGAO table")

    return json.dumps(
        normalized, sort_keys=True, separators=(",", ":")
    )


def reference_from_policy(policy):
    """Compile a trusted policy in a disposable network namespace."""
    result = subprocess.run(
        [
            "unshare", "--net", "--", "sh", "-c",
            "nft -f - && nft -j list table inet wgao_demo"
        ],
        input=policy,
        text=True,
        capture_output=True,
        check=True,
    )
    return signature(result.stdout)


def render_current(config, groups):
    """Rebuild policy using currently authorized client IPs."""
    if set(groups) != set(config["groups"]):
        raise ValueError("Group policy mismatch")

    lines = ["table inet wgao_demo {"]

    for group in sorted(groups, key=int):
        ips = sorted(groups[group], key=ipaddress.IPv4Address)

        if any(
            ipaddress.IPv4Address(ip) not in IP_POOL
            for ip in ips
        ):
            raise ValueError("Unauthorized VPN IP")

        lines += [
            f"    set clients_g{group} {{",
            "        type ipv4_addr;"
        ]

        if ips:
            lines.append(
                f"        elements = {{ {', '.join(ips)} }};"
            )
        lines.append("    }")

    lines += [
        "    chain forward {",
        "        type filter hook forward priority filter; policy drop;",
        "        ct state invalid drop",
    ]

    vpn = config["vpn_interface"]
    target = config["resource_interface"]

    for group in sorted(groups, key=int):
        for dest, port in config["groups"][group]:
            lines.append(
                f'        iifname "{vpn}" oifname "{target}" '
                f'ip saddr @clients_g{group} ip daddr {dest} '
                f'tcp dport {port} ct state new,established accept'
            )
            lines.append(
                f'        iifname "{target}" oifname "{vpn}" '
                f'ip saddr {dest} tcp sport {port} '
                f'ip daddr @clients_g{group} ct state established accept'
            )

    return "\n".join(lines + ["    }", "}", ""])


def repair(ns, config, groups, run):
    """Atomically replace only the WGAO-owned table."""
    batch = (
        "delete table inet wgao_demo\n"
        + render_current(config, groups)
    )

    # Validate transaction before executing it.
    run(ns, "nft", "-c", "-f", "-", stdin=batch)
    run(ns, "nft", "-f", "-", stdin=batch)
