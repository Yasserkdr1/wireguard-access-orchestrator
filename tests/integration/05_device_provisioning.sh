#!/usr/bin/env bash
# Loaded by the integration runner.
test_device_provisioning() {
echo '[PROVISION] Automatic provisioning of a new VPN client...'

# Generate second client's keys locally
wg genkey > "$RUN_DIR/client2.key"
CLIENT2_PUBLIC=$(wg pubkey < "$RUN_DIR/client2.key")

# Register device in SQLite ONLY
REG2=$(PYTHONPATH=src python3 -m wgao \
    --db "$RUN_DIR/peers.sqlite3" register \
    --user-id 8 \
    --label auto-provision \
    --public-key "$CLIENT2_PUBLIC")

read -r DEVICE2_ID CLIENT2_CIDR < <(
    printf '%s\n' "$REG2" | python3 -c '
import json, sys
r = json.JSONDecoder().raw_decode(sys.stdin.read())[0]
print(r["device_id"], r["ip"])
'
)

CLIENT2_IP="${CLIENT2_CIDR%/*}"

# Configure CLIENT side only — NOT gateway
ip netns exec "$CLIENT_NS" ip link add wg1 type wireguard

ip netns exec "$CLIENT_NS" wg set wg1 \
    private-key "$RUN_DIR/client2.key" \
    peer "$GW_PUBLIC" \
    endpoint 192.0.2.1:51820 \
    allowed-ips 10.200.1.0/24

ip -n "$CLIENT_NS" addr add "$CLIENT2_CIDR" dev wg1
ip -n "$CLIENT_NS" link set wg1 up

# Wait for automatic gateway provisioning
T0=$(date +%s%3N)
PROVISIONED=0

for ((i=0; i<40; i++)); do
    if ! kill -0 "$RECON_PID" 2>/dev/null; then
        echo "FAIL: reconciler stopped"
        cat "$RUN_DIR/reconciler.log"
        exit 1
    fi

    if ip netns exec "$GW_NS" wg show wg0 allowed-ips |
        awk -v key="$CLIENT2_PUBLIC" -v addr="$CLIENT2_CIDR" \
            '$1==key && $2==addr {found=1} END {exit !found}' &&
       ip netns exec "$GW_NS" \
           nft list set inet wgao_demo clients_g1 |
        grep -Fq "$CLIENT2_IP"; then
        PROVISIONED=1
        break
    fi

    sleep 0.25
done

if (( PROVISIONED != 1 )); then
    echo "FAIL: automatic provisioning timed out"
    cat "$RUN_DIR/reconciler.log"
    exit 1
fi

echo "PASS: gateway peer + nftables provisioned in $(($(date +%s%3N)-T0)) ms"

# Route test traffic through the NEW WireGuard interface
ip -n "$CLIENT_NS" route replace 10.200.1.10/32 dev wg1

ROUTE2=$(ip netns exec "$CLIENT_NS" \
    ip -4 route get 10.200.1.10)

if [[ "$ROUTE2" != *" dev wg1 "* ||
      "$ROUTE2" != *" src $CLIENT2_IP "* ]]; then
    echo "FAIL: test traffic is not sourced from new client"
    echo "$ROUTE2"
    exit 1
fi

# Test allowed and forbidden traffic
can_connect "$CLIENT_NS" 443 || {
    echo "FAIL: new client cannot access TCP/443"
    exit 1
}

if can_connect "$CLIENT_NS" 444; then
    echo "FAIL: new client reached forbidden TCP/444"
    exit 1
fi

# Confirm real WireGuard handshake for second peer
HANDSHAKE2=$(ip netns exec "$GW_NS" \
    wg show wg0 latest-handshakes |
    awk -v key="$CLIENT2_PUBLIC" '$1==key {print $2}')

if [[ ! "$HANDSHAKE2" =~ ^[0-9]+$ ]] ||
   (( HANDSHAKE2 == 0 )); then
    echo "FAIL: second peer handshake missing"
    exit 1
fi

echo "PASS: new client connected; firewall policy enforced"
}
