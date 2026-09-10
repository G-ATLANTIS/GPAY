# GPAY payment hardening notes

Current branch guarantees:

- Missing provider credentials fail closed.
- Mollie callbacks require an HTTPS public base URL for payment creation.
- Mollie webhook state is re-read from Mollie rather than trusted from callback payload.
- Completed provider payment IDs are persisted and duplicate callbacks after completion return the existing receipt hash.
- Receipts use deterministic SHA-256 hashing over canonical transaction fields.

Not yet guaranteed:

- Crash-safe exactly-once downstream side effects. Reward generation and invoice/email must themselves support idempotency or participate in an atomic transaction before this can be claimed.
- Multi-process/distributed locking for the JSON idempotency store.
- Production deployment or completed live payment evidence.
- Cryptographic signatures over receipt hashes.

Do not describe the current branch as production-ready or as exactly-once settlement infrastructure until those gaps are closed and tested.
