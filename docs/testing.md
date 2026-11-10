# Verification and performance evidence

Unit tests run without privileges from `tests/unit/`. Integration tests run from `tests/integration/`, using the shared disposable topology created by `scripts/lab/lib/`.

| Scenario | Verification |
|---|---|
| Connectivity | Real WireGuard handshake, TCP/443 allowed, TCP/444 denied |
| Drift remediation | Missing peer restored, rogue peer removed, nftables membership restored |
| Firewall integrity | Unauthorized TCP/444 accept rule detected and repaired |
| Provisioning | Second peer registered in SQLite and automatically provisioned |
| Group change | Old access revoked and public key retired |
| Revocation | Database-only change removes live access |
| Active fail-closed | Connected VPN client blocked after invalid trusted roster |

## Commands

```bash
python3 -m unittest discover -s tests/unit -v
sudo bash scripts/run_integration.sh all
python3 tools/metrics.py summary metrics/results/*.json
```

The metrics collector saves a JSON report for each scenario. It checks both process exit status and required success messages. Durations are real observations from the executing environment.

The summary calculates sample count, minimum, median and maximum. Repeat the tests before publishing representative performance figures. Never claim service-level guarantees or p95 latencies from a single run.

GitHub Actions runs unprivileged unit tests and syntax checks. Full network integration tests must run on Kali with namespace privileges.
