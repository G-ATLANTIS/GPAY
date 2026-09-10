# Next hardening step

Before claiming exactly-once processing, make each downstream side effect idempotent by a stable event identifier derived from provider + payment ID + operation. At minimum:

- reward issuance must reject/reuse duplicate event IDs;
- invoice generation must be deterministic or deduplicate by order/provider payment ID;
- mail delivery should be recorded so retries do not send duplicates;
- processing state should support RESERVED -> EFFECTS_APPLIED -> COMMITTED with crash recovery;
- distributed/multi-process deployment should use a transactional datastore or lock primitive rather than a single JSON file.

Only after tests demonstrate replay, crash recovery, and concurrency behavior should the status be upgraded to exactly-once semantics.
