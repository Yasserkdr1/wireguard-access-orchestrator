# WireGuard Access Orchestrator

Standalone Network Security automation project extracted and generalized from the
AppsClub CTF infrastructure. Current stage: **Stage 2 - local device registry**.

Goal: WireGuard peer lifecycle + dynamic group-based access control through
nftables + reconciliation of intended and enforced network state.

## Current behavior (Stage 2)

- Trusted local users/groups loaded from `config/roster.example.json`
- Public-key registration (clients own their private keys)
- SQLite device registry with unique IP allocation and 2-device limit
- Revocation and roster-change reconciliation **in local registry only**
- Read-only snapshot of intended access per group
- **No WireGuard or nftables changes yet**, no cloud or root required

`legacy/` retains code from the original CTF project for comparison; do **not**
run the legacy broker directly on Kali.

## Kali quick start

```bash
# Run as kali (not root), from the Windows-shared project directory
python3 -m unittest discover -s tests -p 'test_*.py' -v
PYTHONPATH=src python3 -m wgao users

# A disposable *demo* key; its private half is discarded, so this peer is
# only for testing registration, not establishing a tunnel.
PUBKEY=$(wg genkey | wg pubkey)
PYTHONPATH=src python3 -m wgao register --user-id 7 --label Kali-Test --public-key "$PUBKEY"
PYTHONPATH=src python3 -m wgao devices
PYTHONPATH=src python3 -m wgao policy
```

See [STAGE2.md](STAGE2.md) for revocation and group-change scenarios.

The database defaults to `~/.local/state/wgao/peers.sqlite3` on **Kali**, so
it is kept off Windows shared folders and out of Git. Do not use `sudo` for
this stage. The trusted admin CLI is not a login or user-facing API.

## Planned stages

- Stage 3: dedicated nftables table/set generation with dry-run and tests
- Stage 4: real WireGuard gateway integration and enforcement in Linux namespaces
- Stage 5: revocation of existing flows, failure/recovery tests, architecture diagram

## Provenance

The original project implemented WireGuard peers and team-based filtering for
CTF challenges. This standalone project separates provisioning, identity and
policy evaluation from CTFd/Kubernetes. It is not a separate, independently
invented implementation and is not production-ready.

## Security boundary

The local JSON roster is trusted test data. Never expose an API where the
caller can submit arbitrary `user_id` without verified authentication and
authorization. Keep secrets, private client keys and live WireGuard configs
outside the repository.
