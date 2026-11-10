#!/usr/bin/env bash
# Disposable isolated network test environment.
# Uses an isolated throwaway SQLite registry and short-lived WireGuard keys.
set -Eeuo pipefail
umask 077

if (( EUID != 0 )); then
    echo 'ERROR: run with sudo bash scripts/live_wg_nft_lab.sh (network namespaces require root)' >&2
    exit 1
fi

for cmd in ip wg nft python3 mktemp; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: missing tool: $cmd" >&2
        exit 1
    fi
done

# Always run from the project's root. Never use /mnt for secret keys or SQLite.
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
[[ -f src/wgao/nft_policy.py && -f config/resources.example.json && -f config/roster.example.json ]] || {
    echo 'ERROR: required project files missing' >&2; exit 1;
}

RUN_DIR=$(mktemp -d /tmp/wgao-live-XXXXXXXX)
ROSTER_FILE="$RUN_DIR/roster.json"
cp config/roster.example.json "$ROSTER_FILE"
TOKEN="${BASHPID}${RANDOM}"
GW_NS="wgao-gw-$TOKEN"
CLIENT_NS="wgao-cl-$TOKEN"
RESOURCE_NS="wgao-sv-$TOKEN"
WAN_A="wa${TOKEN: -8}a"; WAN_B="wa${TOKEN: -8}b"
LAN_A="wl${TOKEN: -8}a"; LAN_B="wl${TOKEN: -8}b"
CREATED_NS=()
PIDS=()
cleanup() {
    set +e
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null; done
    for ns in "${CREATED_NS[@]}"; do ip netns del "$ns" >/dev/null 2>&1; done
    # If a setup step failed before moving veth endpoints, remove temporary host-side veths.
    ip link del "$WAN_A" >/dev/null 2>&1
    ip link del "$WAN_B" >/dev/null 2>&1
    ip link del "$LAN_A" >/dev/null 2>&1
    ip link del "$LAN_B" >/dev/null 2>&1
    rm -rf -- "$RUN_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

