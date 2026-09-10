# GPAY payment hardening — next milestones

The local crash-recovery state machine is implemented, but it is not a substitute for distributed transactionality.

Next milestones, in order:

1. **Distributed persistence and locking**
   - Move payment state and idempotency records from JSON files to a transactional datastore.
   - Enforce a unique key on `(provider, providerPaymentId)`.
   - Use transactional compare-and-set or row locking for stage transitions.
   - Preserve monotonic `RECEIVED -> PROVIDER_VERIFIED -> EFFECTS_PREPARED -> COMMITTED` semantics.

2. **Side-effect idempotency**
   - Stable operation IDs for reward, invoice and notification events.
   - Persist per-effect completion independently.
   - Resume only incomplete effects after restart.
   - Do not claim exactly-once for third-party effects unless the provider itself offers idempotency and the receipt proves it.

3. **Production deployment proof**
   - Deploy behind a real HTTPS endpoint.
   - Run `npm run preflight:production` with authorized runtime configuration.
   - Capture deployment ID and commit provenance.

4. **First authorized live payment evidence**
   - Execute only after explicit authorization.
   - Re-read payment state from Mollie.
   - Capture the tamper-evident evidence bundle.
   - Sign it with a separately provisioned GPAY evidence key if available.

5. **External GCOIN settlement**
   - Separate authorization boundary.
   - No signer/broadcast path is enabled by this branch.
