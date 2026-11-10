# Security model and limitations

- **Trusted identity:** roster and resource policy files are administrator-maintained. They do not authenticate external users. The local CLI must not be exposed as an unprotected API.
- **Privileges:** the network tests run as root but are limited to disposable `wgao-gw-*` namespaces. Running writable shared-folder code as root is appropriate only in a trusted lab, not a production deployment.
- **Firewall scope:** the WGAO-owned table controls forwarded IPv4 TCP traffic. Other nftables tables, UDP, IPv6 and host INPUT traffic are outside the policy integrity guarantee.
- **Tunnel recovery:** restoring a server peer does not always recover an existing client session transparently.
- **Fail-closed:** a running reconciler can disable the lab VPN after detecting invalid roster data. SIGKILL, a failed lockdown, OS outages and a stopped reconciler are not covered.
- **IP allocation:** SQLite avoids duplicates in its registry but does not discover every unrelated static WireGuard peer. Use a dedicated pool.
- **Secrets:** do not commit private keys, runtime databases, tokens or raw operational logs.
- **Threat model:** a privileged attacker capable of terminating the reconciler or installing unrelated host rules is outside the protection guarantees.
