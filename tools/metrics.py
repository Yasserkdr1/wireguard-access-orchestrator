"""Local integration measurements."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from statistics import median

PATTERNS = {
    "peer_restoration_ms":
        r"authorized peer restored in (\d+) ms",
    "rogue_peer_removal_ms":
        r"unauthorized peer removed in (\d+) ms",
    "nft_set_restoration_ms":
        r"nftables access restored in (\d+) ms",
    "provisioning_ms":
        r"gateway peer \+ nftables provisioned in (\d+) ms",
    "group_change_revocation_ms":
        r"group-change network revocation in (\d+) ms",
}

REQUIRED = {
    "full": [
        "PASS: WireGuard handshake observed",
        "PASS: all three security drift tests completed",
        "PASS: unauthorized firewall rule removed",
        "PASS: new client connected; firewall policy enforced",
        "PASS: old VPN access revoked",
        "PASS: automatic WireGuard + nftables revocation",
        "SUCCESS: complete VPN access lifecycle",
    ],
    "active-fail-closed": [
        "PASS: authorized VPN client is connected",
        "PASS: WireGuard gateway interface disabled",
        "PASS: previously authorized client is now blocked",
        "SUCCESS: ACTIVE VPN fail-closed validated",
    ],
}

def parse_log(text, scenario, exit_code=0):
    if scenario not in REQUIRED:
        raise ValueError("Unknown scenario")

    checks = {
        marker: marker in text
        for marker in REQUIRED[scenario]
    }

    measurements = {
        name: [int(x) for x in re.findall(pattern, text)]
        for name, pattern in PATTERNS.items()
    }

    return {
        "schema_version": 1,
        "utc": datetime.now(timezone.utc).isoformat(),
        "scenario": scenario,
        "exit_code": exit_code,
        "passed": exit_code == 0 and all(checks.values()),
        "checks": checks,
        "durations_ms": {
            k: v for k, v in measurements.items() if v
        },
    }

def summarize(files):
    reports = [
        json.loads(p.read_text())
        for p in files if p.is_file()
    ]

    passed = sum(x["passed"] for x in reports)
    lines = [f"Passed runs: {passed}/{len(reports)}"]

    for name in PATTERNS:
        values = [
            duration
            for report in reports
            for duration in report[
                "durations_ms"
            ].get(name, [])
        ]

        if values:
            lines.append(
                f"{name}: n={len(values)}, "
                f"min={min(values)}, "
                f"median={median(values):g}, "
                f"max={max(values)} ms"
            )

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(
        dest="command", required=True
    )

    collect = sub.add_parser("collect")
    for name in ["scenario", "exit-code", "log", "output"]:
        collect.add_argument("--" + name, required=True)

    summary = sub.add_parser("summary")
    summary.add_argument(
        "files", type=Path, nargs="*"
    )

    args = parser.parse_args()

    if args.command == "collect":
        report = parse_log(
            Path(args.log).read_text(errors="replace"),
            args.scenario,
            int(args.exit_code)
        )

        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, indent=2) + "\n"
        )

        print(
            f"Metrics: {output} "
            f"({'PASS' if report['passed'] else 'FAIL'})"
        )

        if not report["passed"] and report["exit_code"] == 0:
            parser.exit(
                3, "ERROR: expected test evidence missing\n"
            )
    else:
        print(summarize(args.files))

if __name__ == "__main__":
    main()
