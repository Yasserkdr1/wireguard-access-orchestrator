#!/usr/bin/env bash
# Loaded by the integration runner.
test_peer_and_set_drift() {
echo '[7/7] Testing automatic security drift correction...'

# TEST A: An authorized WireGuard peer disappears
echo '[DRIFT A] Removing an authorized peer...'

T0=$(date +%s%3N)

ip netns exec "$GW_NS" wg set wg0 \
    peer "$CLIENT_PUBLIC" remove

REPAIRED=0

for ((i=0; i<40; i++)); do
    if ! kill -0 "$RECON_PID" 2>/dev/null; then
        echo "FAIL: reconciler stopped"
        cat "$RUN_DIR/reconciler.log"
        exit 1
    fi

    if ip netns exec "$GW_NS" wg show wg0 allowed-ips |
        awk -v key="$CLIENT_PUBLIC" '
            $1 == key && $2 == "10.77.0.100/32" {
                found=1
            }
            END { exit !found }
        '; then
        REPAIRED=1
        break
    fi

    sleep 0.25
done

if (( REPAIRED != 1 )); then
    echo "FAIL: authorized WireGuard peer not restored"
    cat "$RUN_DIR/reconciler.log"
    exit 1
fi

echo "PASS: authorized peer restored in $(($(date +%s%3N)-T0)) ms"


echo '[CHECK] Testing traffic after WireGuard peer restoration...'

if can_connect "$CLIENT_NS" 443; then
    echo "PASS: original client traffic recovered automatically"
else
    echo "INFO: peer restored, but VPN session not yet recovered"
    echo "INFO: forcing a new client-side WireGuard handshake"

    # Reset the CLIENT peer to initiate a new session.
    # This is a lab recovery test, not automatic server-side healing.
    ip netns exec "$CLIENT_NS" wg set wg0 \
        peer "$GW_PUBLIC" remove

    ip netns exec "$CLIENT_NS" wg set wg0 \
        peer "$GW_PUBLIC" \
        endpoint 192.0.2.1:51820 \
        allowed-ips 10.200.1.0/24

    if ! can_connect "$CLIENT_NS" 443; then
        echo "FAIL: traffic not recovered after client rekey"
        ip netns exec "$CLIENT_NS" wg show wg0
        ip netns exec "$GW_NS" wg show wg0
        exit 1
    fi

    echo "PASS: original client recovered after handshake reset"
fi

# TEST B: An unauthorized peer is injected
echo '[DRIFT B] Injecting an unauthorized peer...'

UNKNOWN_PUBLIC=$(wg genkey | wg pubkey)
T0=$(date +%s%3N)

ip netns exec "$GW_NS" wg set wg0 \
    peer "$UNKNOWN_PUBLIC" \
    allowed-ips 10.77.0.200/32

REMOVED=0

for ((i=0; i<40; i++)); do
    if ! kill -0 "$RECON_PID" 2>/dev/null; then
        echo "FAIL: reconciler stopped"
        cat "$RUN_DIR/reconciler.log"
        exit 1
    fi

    if ! ip netns exec "$GW_NS" wg show wg0 peers |
        grep -Fxq "$UNKNOWN_PUBLIC"; then
        REMOVED=1
        break
    fi

    sleep 0.25
done

if (( REMOVED != 1 )); then
    echo "FAIL: unauthorized peer still exists"
    cat "$RUN_DIR/reconciler.log"
    exit 1
fi

echo "PASS: unauthorized peer removed in $(($(date +%s%3N)-T0)) ms"


# TEST C: An authorized nftables entry disappears
echo '[DRIFT C] Removing an authorized nftables element...'

T0=$(date +%s%3N)

ip netns exec "$GW_NS" nft delete element \
    inet wgao_demo clients_g1 '{ 10.77.0.100 }'

RESTORED=0

for ((i=0; i<40; i++)); do
    if ! kill -0 "$RECON_PID" 2>/dev/null; then
        echo "FAIL: reconciler stopped"
        cat "$RUN_DIR/reconciler.log"
        exit 1
    fi

    if ip netns exec "$GW_NS" \
        nft list set inet wgao_demo clients_g1 |
        grep -Fq '10.77.0.100'; then
        RESTORED=1
        break
    fi

    sleep 0.25
done

if (( RESTORED != 1 )); then
    echo "FAIL: nftables permission not restored"
    cat "$RUN_DIR/reconciler.log"
    exit 1
fi

echo "PASS: nftables access restored in $(($(date +%s%3N)-T0)) ms"

echo "PASS: all three security drift tests completed"
}
