# Stage 2 — Local device registry (NO network changes)

The implementation in `src/wgao/broker.py` extracts the core ideas from
`legacy/appsclub_vpn_broker.py`: SQLite registry, IP address allocation,
per-user device limits, retired-key tracking, membership-change revocation.

The local CLI is **administrator-operated** and reads an example JSON roster.
It is NOT a multiuser authentication service. Do not expose it as an API.

## Running from Kali

Work in the mounted project source as regular user `kali`, not `root`.
The SQLite state is deliberately written to Kali's Linux filesystem, not the
Windows shared folder.

```bash
cd /mnt  # if your mounted repository root is /mnt
python3 -m unittest discover -s tests -p 'test_*.py' -v
PYTHONPATH=src python3 -m wgao --roster config/roster.example.json users
```

For the offline demo only, generate a public key. The temporary private key is
**discarded**, so this demo peer cannot be used for a later VPN handshake.
In Stage 4, we'll create a proper client-owned key pair and keep its private key
outside Git:

```bash
PUBKEY=$(wg genkey | wg pubkey)
PYTHONPATH=src python3 -m wgao register --user-id 7 --label Kali-Test --public-key "$PUBKEY"
PYTHONPATH=src python3 -m wgao devices
PYTHONPATH=src python3 -m wgao policy
```

To revoke a device manually, copy the `device_id` printed by `devices`:

```bash
PYTHONPATH=src python3 -m wgao revoke --device-id YOUR_DEVICE_ID
```

To test membership change, edit `config/roster.example.json` on **Windows**,
remove user 7 or change their `group_id`, then run:

```bash
PYTHONPATH=src python3 -m wgao reconcile
PYTHONPATH=src python3 -m wgao devices
```

Restore the example roster in Git after testing. All these commands operate
only on the local SQLite state, without modifying WireGuard or nftables.

**Next:** build a dry-run nftables renderer against `policy` output, then add
Linux network namespace integration tests before touching the real firewall.
