#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

mode="${1:-all}"

if [[ "$mode" == all ]]; then
    if (( EUID != 0 )); then
        echo "Run this suite with sudo" >&2
        exit 1
    fi

    mkdir -p metrics/results

    for scenario in full active-fail-closed; do
        echo "========== INTEGRATION: $scenario =========="

        log=$(mktemp /tmp/wgao-test-XXXXXXXX.log)

        set +e
        bash scripts/run_integration.sh "$scenario" 2>&1 | tee "$log"
        status=${PIPESTATUS[0]}
        set -e

        stamp=$(date -u +%Y%m%dT%H%M%SZ)

        python3 tools/metrics.py collect \
            --scenario "$scenario" \
            --exit-code "$status" \
            --log "$log" \
            --output "metrics/results/${stamp}-${BASHPID}-${scenario}.json"

        rm -f "$log"

        if (( status != 0 )); then
            echo "FAIL: $scenario" >&2
            exit "$status"
        fi
    done

    python3 tools/metrics.py summary metrics/results/*.json
    exit 0
fi

if [[ "$mode" != full && "$mode" != active-fail-closed ]]; then
    echo "Usage: sudo bash scripts/run_integration.sh [all|full|active-fail-closed]" >&2
    exit 2
fi

source scripts/lab/lib/common.sh
source scripts/lab/lib/topology.sh
source scripts/lab/lib/reconciler.sh

for file in tests/integration/[0-9][0-9]_*.sh; do
    source "$file"
done

setup_network
test_connectivity

if [[ "$mode" == active-fail-closed ]]; then
    export WGAO_TEST_ACTIVE_FAIL_CLOSED=1
    test_active_fail_closed
    exit 0
fi

start_reconciler
test_peer_and_set_drift
test_firewall_integrity
test_device_provisioning
test_group_change
test_revocation

echo "SUCCESS: complete VPN access lifecycle and policy validation."
