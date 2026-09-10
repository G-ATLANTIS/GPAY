# GPAY payment hardening notes

Current branch guarantees:

- Missing provider credentials fail closed.
- Mollie callbacks require an HTTPS public base URL for payment creation.
- Mollie webhook is mounted at the advertised `/api/mollie/webhook` path.
- Mollie webhook state is re-read from Mollie rather than trusted from callback payload.
- Completed provider payment IDs are persisted and duplicate callbacks after completion return the existing receipt hash.
- Receipts use deterministic SHA-256 hashing over canonical transaction fields.
- Payment processing records monotonic local recovery stages: `RECEIVED -> PROVIDER_VERIFIED -> EFFECTS_PREPARED -> COMMITTED`.
- Retries reuse the original `processedAt` timestamp so a crash/restart does not silently change the reconstructed receipt identity.
- Stage rollback is denied.
- The local recovery-state file is written through a temp file, fsynced, then atomically renamed.
- GCOIN integration remains settlement-intent only: no signer, mint, transfer or blockchain broadcast.
- Tamper-evident evidence bundles and optional runtime-only Ed25519 evidence signing are implemented.

Not yet guaranteed:

- Exactly-once semantics for external side effects across crashes. Current recovery reduces ambiguity but cannot atomically commit third-party side effects with local state.
- Multi-process or multi-host distributed locking/transactions. The current state store is a single-filesystem pre-production implementation.
- Production deployment or completed live payment evidence.
- A production evidence-signing key being provisioned.
- External GCOIN settlement.

Do not describe the current branch as production-ready, distributed exactly-once infrastructure, or as having completed a live GCOIN settlement until those milestones are separately verified.
