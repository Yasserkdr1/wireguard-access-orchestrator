# Access lifecycle and security workflows

## Device provisioning and revocation

```mermaid
flowchart TD
  A[Register public key] --> B{User authorized and device limit respected?}
  B -- No --> X[Reject request]
  B -- Yes --> C[Allocate VPN IP in SQLite]
  C --> D[Reconciler creates WireGuard peer]
  D --> E[Update nftables group set]
  E --> F{Destination and TCP port permitted?}
  F -- No --> Z[Drop traffic]
  F -- Yes --> G[Forward traffic]
  G --> H{Revoked or group changed?}
  H -- No --> D
  H -- Yes --> I[Remove peer and old authorization]
  I --> J[Retire old public key]
```

## Reconciliation and fail-closed

```mermaid
flowchart TD
  A[Reconciliation tick] --> B{Trusted roster valid?}
  B -- No --> K[Fail closed: disable wg0]
  B -- Yes --> C{Owned nftables policy intact?}
  C -- No --> D[Atomically restore owned table]
  C -- Yes --> E[Compare peers and dynamic sets]
  D --> F{Repair verified?}
  F -- No --> K
  F -- Yes --> E
  E --> G{Access drift detected?}
  G -- No --> A
  G -- Yes --> H[Apply access corrections]
  H --> I{Commands succeeded?}
  I -- No --> K
  I -- Yes --> A
```

Recreating a missing server-side WireGuard peer sometimes requires a client-side handshake reset to restore connectivity. The laboratory tests and documents this behavior.
