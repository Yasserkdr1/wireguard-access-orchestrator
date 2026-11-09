# WireGuard Access Orchestrator - Stage 1 (local prototype)

Goal: evolve the existing CTF WireGuard broker + iptables controller into a
standalone WireGuard provisioning / **nftables** access orchestration system.

## Stage 1: offline identity roster + retained source

- `legacy/appsclub_vpn_broker.py` and `legacy/appsclub_vip_controller.py` are
  **unaltered copies** of the user's CTF implementation for review/refactoring.
  **Do not run them directly**: they contain deployment-specific paths, IPs and
  system network commands targeting an existing WireGuard interface.
- `src/wgao/roster.py` implements an independent fail-closed local roster parser.
- `config/roster.example.json` holds fake local demo identities.
- `tests/` contains the adapted original unit tests plus new roster tests.

This stage is deliberately **non-privileged**: it does NOT provision WG peers,
add nftables rules, or establish a VPN. The JSON roster is for a **trusted
local demo only**, not end-user authentication. No internet/cloud required.

## On Kali (no sudo)

```bash
cd wireguard-access-orchestrator-starter
python3 -m unittest discover -s tests -p 'test_*.py' -v
PYTHONPATH=src python3 -m wgao --roster config/roster.example.json
```

Expected: tests pass, then 3 demo users are printed; no system network
settings are changed. The original tests use mocked subprocess calls and
temporary SQLite files, rather than real peers.

## Next stages

2. Make broker configuration non-root and injectable. Replace its CTFd roster
   lookup with the local provider for demo; keep authenticated callers.
3. Build a scoped nftables backend with a dedicated `inet wgao` table and
   `default-deny` filtering. Start by rendering rules without applying them.
4. Integrate WireGuard peers and test on Linux network namespaces on one VM.
5. Test revocation, reconciliation, rollback and enforcement for existing flows.

## Safety and publication

- Review both legacy sources before publishing; they contain old infrastructure
  addresses/paths. Keep secrets, tokens and `.conf` files out of Git.
- Never execute `flush ruleset` or run legacy broker with `sudo` on Kali.
- GitHub README should link to the original CTF project and state that this
  standalone orchestrator was extracted and generalized from it.
