#!/usr/bin/env bash
# Loaded by the integration runner.
start_reconciler() {
echo '[7/7] Testing automatic reconciliation...'

# Start reconciler in background
PYTHONPATH=src python3 -u -m wgao.live_sync \
    --namespace "$GW_NS" \
    --db "$RUN_DIR/peers.sqlite3" \
    --roster "$ROSTER_FILE" \
    --resources config/resources.example.json \
    --apply \
    --watch \
    --interval 0.25 \
    > "$RUN_DIR/reconciler.log" 2>&1 &

RECON_PID=$!
PIDS+=("$RECON_PID")

sleep 0.5

if ! kill -0 "$RECON_PID" 2>/dev/null; then
    echo "FAIL: reconciler failed to start"
    cat "$RUN_DIR/reconciler.log"
    exit 1
fi
}
