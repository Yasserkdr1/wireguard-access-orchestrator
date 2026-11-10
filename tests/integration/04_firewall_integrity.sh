#!/usr/bin/env bash
# Loaded by the integration runner.
test_firewall_integrity() {
echo '[FIREWALL DRIFT] Injecting unauthorized TCP/444 ACCEPT...'

ip netns exec "$GW_NS" nft insert rule inet wgao_demo forward \
    iifname "wg0" oifname "eth1" \
    ip saddr 10.77.0.100 ip daddr 10.200.1.10 \
    tcp dport 444 accept

REPAIRED_RULES=0

for ((i=0; i<40; i++)); do
    if ! kill -0 "$RECON_PID" 2>/dev/null; then
        echo 'FAIL: reconciler stopped'
        cat "$RUN_DIR/reconciler.log"
        exit 1
    fi

    if grep -Fq 'FIREWALL-REPAIRED:' \
           "$RUN_DIR/reconciler.log" &&
       ! ip netns exec "$GW_NS" \
           nft list chain inet wgao_demo forward |
           grep -Fq 'tcp dport 444'; then

        REPAIRED_RULES=1
        break
    fi

    sleep 0.25
done

if (( REPAIRED_RULES != 1 )); then
    echo 'FAIL: unauthorized firewall rule not repaired'
    cat "$RUN_DIR/reconciler.log"
    exit 1
fi

if can_connect "$CLIENT_NS" 444; then
    echo 'FAIL: forbidden TCP/444 remains accessible'
    exit 1
fi

can_connect "$CLIENT_NS" 443 || {
    echo 'FAIL: authorized TCP/443 no longer works'
    exit 1
}

echo 'PASS: unauthorized firewall rule removed'
echo 'PASS: default-deny policy restored'
}
