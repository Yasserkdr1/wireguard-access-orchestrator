#!/usr/bin/env bash
# Loaded by the integration runner.
test_connectivity() {
echo '[6/7] Live forwarding tests: allowed 443, blocked 444...'
can_connect "$CLIENT_NS" 443 || { echo 'FAIL: allowed client->service TCP/443 flow blocked' >&2; exit 1; }
if can_connect "$CLIENT_NS" 444; then
    echo 'FAIL: forbidden client->service TCP/444 flow unexpectedly allowed' >&2
    exit 1
fi
HANDSHAKE=$(ip netns exec "$GW_NS" wg show wg0 latest-handshakes | awk '{print $2}')
if [[ ! "$HANDSHAKE" =~ ^[0-9]+$ ]] || (( HANDSHAKE == 0 )); then
    echo 'FAIL: no WireGuard handshake was observed' >&2
    exit 1
fi
echo 'PASS: WireGuard handshake observed; allowed/blocked network policy enforced.'
}
