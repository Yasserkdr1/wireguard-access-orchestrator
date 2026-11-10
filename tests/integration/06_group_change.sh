#!/usr/bin/env bash
# Loaded by the integration runner.
test_group_change() {
# WGAO_GROUP_CHANGE_TEST_V1
echo '[GROUP CHANGE] Moving user 8 from group 1 to group 2...'

# Atomically modify the temporary trusted roster.
python3 - "$ROSTER_FILE" <<'PYROSTER'
import json
import os
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = json.loads(path.read_text())

users = [
    user for user in data["members"]
    if user["user_id"] == 8
]

if len(users) != 1 or users[0]["group_id"] != 1:
    raise SystemExit("Unexpected user membership")

users[0]["group_id"] = 2

temporary = path.with_suffix(".tmp")
temporary.write_text(json.dumps(data, indent=2))
os.replace(temporary, path)
PYROSTER

T0=$(date +%s%3N)
GROUP_CHANGE_DONE=0

# Wait for automatic network revocation.
for ((i=0; i<40; i++)); do

    if ! kill -0 "$RECON_PID" 2>/dev/null; then
        echo "FAIL: reconciler stopped"
        cat "$RUN_DIR/reconciler.log"
        exit 1
    fi

    if ! ip netns exec "$GW_NS" wg show wg0 peers |
        grep -Fxq "$CLIENT2_PUBLIC" &&
       ! ip netns exec "$GW_NS" \
           nft list set inet wgao_demo clients_g1 |
        grep -Fq "$CLIENT2_IP"; then

        GROUP_CHANGE_DONE=1
        break
    fi

    sleep 0.25
done

if (( GROUP_CHANGE_DONE != 1 )); then
    echo "FAIL: old permissions still active"
    cat "$RUN_DIR/reconciler.log"
    exit 1
fi

echo "PASS: group-change network revocation in $(($(date +%s%3N)-T0)) ms"

# Verify local registry cleanup and key retirement.
DB_CLEAN=0

for ((i=0; i<40; i++)); do

    if python3 - "$RUN_DIR/peers.sqlite3" "$CLIENT2_PUBLIC" <<'PYDB'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1], timeout=2) as db:
    active = db.execute(
        "SELECT 1 FROM devices WHERE public_key=?",
        (sys.argv[2],)
    ).fetchone()

    retired = db.execute(
        "SELECT 1 FROM retired_keys WHERE public_key=?",
        (sys.argv[2],)
    ).fetchone()

if active or not retired:
    raise SystemExit(1)
PYDB
    then
        DB_CLEAN=1
        break
    fi

    sleep 0.25
done

if (( DB_CLEAN != 1 )); then
    echo "FAIL: old key not retired"
    exit 1
fi

# The old client's connection must now fail.
if can_connect "$CLIENT_NS" 443; then
    echo "FAIL: old client still has network access"
    exit 1
fi

echo "PASS: old VPN access revoked"
echo "PASS: device removed from registry"
echo "PASS: previous public key retired"
}
