#!/usr/bin/env bash
# Loaded by the integration runner.
setup_network() {
echo '[1/7] Creating isolated namespaces and interfaces...'
for ns in "$GW_NS" "$CLIENT_NS" "$RESOURCE_NS"; do
    ip netns add "$ns"
    CREATED_NS+=("$ns")
    ip -n "$ns" link set lo up
done
ip link add "$WAN_A" type veth peer name "$WAN_B"
ip link set "$WAN_A" netns "$GW_NS"
ip link set "$WAN_B" netns "$CLIENT_NS"
ip -n "$GW_NS" link set "$WAN_A" name eth0
ip -n "$CLIENT_NS" link set "$WAN_B" name eth0
ip link add "$LAN_A" type veth peer name "$LAN_B"
ip link set "$LAN_A" netns "$GW_NS"
ip link set "$LAN_B" netns "$RESOURCE_NS"
ip -n "$GW_NS" link set "$LAN_A" name eth1
ip -n "$RESOURCE_NS" link set "$LAN_B" name eth0

ip -n "$GW_NS" addr add 192.0.2.1/30 dev eth0
ip -n "$CLIENT_NS" addr add 192.0.2.2/30 dev eth0
ip -n "$GW_NS" addr add 10.200.1.1/24 dev eth1
ip -n "$RESOURCE_NS" addr add 10.200.1.10/24 dev eth0
for spec in "$GW_NS:eth0" "$GW_NS:eth1" "$CLIENT_NS:eth0" "$RESOURCE_NS:eth0"; do
    ip -n "${spec%:*}" link set "${spec#*:}" up
done
ip -n "$RESOURCE_NS" route add default via 10.200.1.1
ip netns exec "$GW_NS" sysctl -q -w net.ipv4.ip_forward=1

echo '[2/7] Creating real WireGuard peers (keys stored only in /tmp)...'
wg genkey > "$RUN_DIR/gw.key"
wg genkey > "$RUN_DIR/client.key"
GW_PUBLIC=$(wg pubkey < "$RUN_DIR/gw.key")
CLIENT_PUBLIC=$(wg pubkey < "$RUN_DIR/client.key")
ip netns exec "$GW_NS" ip link add wg0 type wireguard
ip netns exec "$CLIENT_NS" ip link add wg0 type wireguard
ip netns exec "$GW_NS" wg set wg0 private-key "$RUN_DIR/gw.key" listen-port 51820 \
    peer "$CLIENT_PUBLIC" allowed-ips 10.77.0.100/32
ip netns exec "$CLIENT_NS" wg set wg0 private-key "$RUN_DIR/client.key" \
    peer "$GW_PUBLIC" endpoint 192.0.2.1:51820 allowed-ips 10.200.1.0/24
ip -n "$GW_NS" addr add 10.77.0.1/24 dev wg0
ip -n "$CLIENT_NS" addr add 10.77.0.100/32 dev wg0
ip -n "$GW_NS" link set wg0 up
ip -n "$CLIENT_NS" link set wg0 up
ip -n "$CLIENT_NS" route add 10.200.1.0/24 dev wg0

echo '[3/7] Registering real client public key with a TEMPORARY local DB...'
REG_OUTPUT=$(PYTHONPATH=src python3 -m wgao --db "$RUN_DIR/peers.sqlite3" register \
    --user-id 7 --label live-test --public-key "$CLIENT_PUBLIC")
DEVICE_ID=$(printf '%s\n' "$REG_OUTPUT" | python3 -c \
    'import json,sys; print(json.JSONDecoder().raw_decode(sys.stdin.read())[0]["device_id"])')
PYTHONPATH=src python3 -m wgao --db "$RUN_DIR/peers.sqlite3" firewall-preview \
    --output "$RUN_DIR/before.nft"
# Prevent mismatched demo config / accidental unrelated policy being loaded.
python3 - "$RUN_DIR/before.nft" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]).read_text()
assert 'table inet wgao_demo {' in p
assert 'iifname "wg0" oifname "eth1"' in p
assert '10.77.0.100' in p
PY

echo '[4/7] Applying generated nftables policy ONLY inside the gateway namespace...'
ip netns exec "$GW_NS" nft -c -f "$RUN_DIR/before.nft"
ip netns exec "$GW_NS" nft -f "$RUN_DIR/before.nft"

echo '[5/7] Starting two LOCAL TCP services (port 443 and forbidden port 444)...'
# These are plain TCP demo servers, NOT TLS. We test PORT filtering, not HTTPS encryption.
ip netns exec "$RESOURCE_NS" python3 -u -m http.server 443 --bind 10.200.1.10 \
    --directory "$RUN_DIR" > "$RUN_DIR/http443.log" 2>&1 & PID443=$!; PIDS+=("$PID443")
ip netns exec "$RESOURCE_NS" python3 -u -m http.server 444 --bind 10.200.1.10 \
    --directory "$RUN_DIR" > "$RUN_DIR/http444.log" 2>&1 & PID444=$!; PIDS+=("$PID444")

# Check actual reachability from the gateway namespace BEFORE testing the firewall.
# A single sleep may not be enough on busy/slow VMs, so use a bounded readiness check.
backend_ready() {
    local port="$1"
    ip netns exec "$GW_NS" python3 - "$port" >/dev/null 2>&1 <<'PYREADY'
import socket, sys
with socket.create_connection(("10.200.1.10", int(sys.argv[1])), timeout=0.5):
    pass
PYREADY
}

wait_for_backend() {
    local port="$1" pid="$2" logfile="$3" i
    for ((i = 0; i < 40; i++)); do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "ERROR: backend TCP/$port exited during startup" >&2
            cat "$logfile" >&2 || true
            return 1
        fi
        if backend_ready "$port"; then
            echo "READY: backend TCP/$port"
            return 0
        fi
        sleep 0.2
    done
    echo "ERROR: backend TCP/$port not reachable from gateway after retries" >&2
    echo "--- backend TCP/$port log ---" >&2
    cat "$logfile" >&2 || true
    echo '--- resource namespace listening ports (if ss available) ---' >&2
    if command -v ss >/dev/null 2>&1; then
        ip netns exec "$RESOURCE_NS" ss -ltnp >&2 || true
    fi
    return 1
}

wait_for_backend 443 "$PID443" "$RUN_DIR/http443.log"
wait_for_backend 444 "$PID444" "$RUN_DIR/http444.log"

can_connect() {
    local ns="$1" port="$2"
    ip netns exec "$ns" python3 -c '
import socket, sys
try:
    s = socket.create_connection(("10.200.1.10", int(sys.argv[1])), timeout=2.5)
    s.close()
except OSError as ex:
    print("BLOCKED:", type(ex).__name__)
    sys.exit(1)
else:
    print("CONNECTED")
' "$port"
}
}
