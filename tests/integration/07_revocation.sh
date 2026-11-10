#!/usr/bin/env bash
# Loaded by the integration runner.
test_revocation() {
# Restore original client's route
echo '[CHECK] Restoring original client routing...'

ip -n "$CLIENT_NS" route del 10.200.1.10/32 dev wg1

ROUTE_ORIGINAL=$(ip netns exec "$CLIENT_NS"     ip -4 route get 10.200.1.10)

echo "Route: $ROUTE_ORIGINAL"

if [[ "$ROUTE_ORIGINAL" != *"dev wg0"* ]] ||
   [[ "$ROUTE_ORIGINAL" != *"src 10.77.0.100"* ]]; then

    echo "FAIL: original client route not restored"
    ip -n "$CLIENT_NS" route show
    exit 1
fi

echo '--- Client WireGuard handshake ---'
ip netns exec "$CLIENT_NS" wg show wg0 latest-handshakes

echo '--- Gateway peers ---'
ip netns exec "$GW_NS" wg show wg0 allowed-ips

echo '--- Authorized nftables clients ---'
ip netns exec "$GW_NS"     nft list set inet wgao_demo clients_g1

if ! can_connect "$CLIENT_NS" 443; then
    echo "FAIL: original client still cannot connect"

    echo '--- Client diagnostics ---'
    ip netns exec "$CLIENT_NS" wg show wg0

    echo '--- Gateway diagnostics ---'
    ip netns exec "$GW_NS" wg show wg0

    exit 1
fi

echo "PASS: original client still operational after second client revocation"

# Revoke ONLY in the database
PYTHONPATH=src python3 -m wgao \
    --db "$RUN_DIR/peers.sqlite3" \
    revoke --device-id "$DEVICE_ID"

# Wait until reconciler removes both permissions
REVOKED=0

for ((attempt=0; attempt<40; attempt++)); do

    if ! kill -0 "$RECON_PID" 2>/dev/null; then
        echo "FAIL: reconciler stopped"
        cat "$RUN_DIR/reconciler.log"
        exit 1
    fi

    if ! ip netns exec "$GW_NS" wg show wg0 peers \
        | grep -Fq "$CLIENT_PUBLIC" && \
       ! ip netns exec "$GW_NS" \
           nft list set inet wgao_demo clients_g1 \
        | grep -Fq '10.77.0.100'; then

        REVOKED=1
        break
    fi

    sleep 0.25
done

if (( REVOKED != 1 )); then
    echo "FAIL: automatic reconciliation timed out"
    cat "$RUN_DIR/reconciler.log"
    exit 1
fi

# Verify access is really blocked
if can_connect "$CLIENT_NS" 443; then
    echo "FAIL: revoked client still has access"
    exit 1
fi

echo "PASS: automatic WireGuard + nftables revocation"
}
