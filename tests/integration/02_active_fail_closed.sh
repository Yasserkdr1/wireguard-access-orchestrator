#!/usr/bin/env bash
# Loaded by the integration runner.
test_active_fail_closed() {
# WGAO_ACTIVE_FAIL_CLOSED_V1
if [[ "${WGAO_TEST_ACTIVE_FAIL_CLOSED:-0}" == "1" ]]; then

    echo '[ACTIVE FAIL-CLOSED] Starting security test...'

    # Start reconciler while the original client is authorized
    PYTHONPATH=src python3 -u -m wgao.live_sync \
        --namespace "$GW_NS" \
        --db "$RUN_DIR/peers.sqlite3" \
        --roster "$ROSTER_FILE" \
        --resources config/resources.example.json \
        --apply --watch --interval 0.25 \
        > "$RUN_DIR/failclosed.log" 2>&1 &

    WATCH_PID=$!
    PIDS+=("$WATCH_PID")

    sleep 0.5

    if ! kill -0 "$WATCH_PID" 2>/dev/null; then
        echo "FAIL: reconciler failed to start"
        cat "$RUN_DIR/failclosed.log"
        exit 1
    fi

    # Prove the VPN access is ACTIVE before the failure
    echo '[CHECK] VPN access before failure...'

    if ! can_connect "$CLIENT_NS" 443; then
        echo "FAIL: client not connected before failure"
        exit 1
    fi

    echo 'PASS: authorized VPN client is connected'

    # Corrupt only our temporary authorization file
    echo '[ATTACK] Corrupting trusted roster...'

    printf '{ invalid json\n' > "$ROSTER_FILE.next"
    mv -f "$ROSTER_FILE.next" "$ROSTER_FILE"

    LOCKED=0

    # Wait until emergency lockdown is triggered
    for ((i=0; i<40; i++)); do

        if grep -Fq \
            'FAIL-CLOSED: wg0 disabled' \
            "$RUN_DIR/failclosed.log" &&
           ip -n "$GW_NS" -j link show dev wg0 |
            python3 -c '
import json,sys
data=json.load(sys.stdin)
sys.exit(0 if "UP" not in data[0].get("flags",[]) else 1)
'; then
            LOCKED=1
            break
        fi

        sleep 0.25
    done

    if (( LOCKED != 1 )); then
        echo "FAIL: emergency lockdown not confirmed"
        cat "$RUN_DIR/failclosed.log"
        exit 1
    fi

    echo 'PASS: WireGuard gateway interface disabled'

    # Confirm previously authorized traffic is now blocked
    echo '[CHECK] VPN access after failure...'

    if can_connect "$CLIENT_NS" 443; then
        echo "FAIL: VPN still accessible after lockdown"
        exit 1
    fi

    echo 'PASS: previously authorized client is now blocked'
    echo 'SUCCESS: ACTIVE VPN fail-closed validated'

    exit 0
fi
}
