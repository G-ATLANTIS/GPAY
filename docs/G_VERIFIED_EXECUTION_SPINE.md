# G_VERIFIED_EXECUTION_SPINE

Status: additive, fail-closed control path. Default posture is **deny**.

One deterministic, executable enforcement path that every state-changing −G
operation in this repository can be routed through. It consolidates primitives
that already existed in `backend/g-bank-live-v1/` and the `scripts/g-payment-*`
lineage into a single callable API.

```
REQUEST → VERIFY_SCOPE → CHECK_PATH → DISCOVER_CAPABILITY → POLICY_CHECK
→ AUTHORIZATION → EXECUTE → VERIFY_READBACK → RECEIPT → AUDIT → COMMIT_STATE
```

Core invariant:

```
UNVERIFIED_EXTERNAL_EFFECT != CANONICAL_SUCCESS

CANONICAL_STATE_MUTATION
    REQUIRES  EXECUTION_AUTHORIZED
    AND       EXECUTION_EVIDENCED
    AND       REQUIRED_VERIFICATION_PASSED
```

## API

```js
const { executeVerified, reconcile } = require('./backend/g-verified-execution-spine');

const result = await executeVerified(request, context); // -> VerifiedExecutionResult
```

`executeVerified` never throws for an expected denial or failure. It always
resolves to a frozen `VerifiedExecutionResult` whose `state` is one of:

| state | meaning |
|---|---|
| `VERIFIED_SUCCESS` | authorized, executed, evidenced, verified, audited, committed |
| `DENIED_SCOPE` | request did not bound exactly one effect |
| `DENIED_POLICY` | default-deny, or an explicit DENY rule matched |
| `DENIED_AUTHORIZATION` | missing / invalid / expired / mis-bound authorization |
| `NO_VERIFIED_PATH` | no registered connector, or discover() below required assurance |
| `PROVIDER_FAILURE` | connector returned a definite provider-side failure (HTTP status) |
| `EXECUTION_UNVERIFIED` | ambiguous outcome; effect may have happened — quarantined |
| `READBACK_MISMATCH` | connector claimed success but readback did not confirm it |
| `REPLAY_REJECTED` | idempotency key reused, or key is quarantined pending reconcile |
| `STALE_STATE_REJECTED` | `expected_sequence` not strictly greater than committed |
| `INTERNAL_FAIL_CLOSED` | any internal error, including audit-write failure |

A `VERIFIED_SUCCESS` is **structurally impossible** without: `policy_hash`,
`authorization_evidence`, `pre_state_hash`, `provider_request_id`,
`execution_result`, a non-`NONE` `verification_method`, `post_state_hash`,
`audit_entry_hash`, `result_sha256`, and `canonical_commit_status = COMMITTED`.
`backend/g-verified-execution-spine/invariants.js` enforces this and is asserted
on every path by the test suite.

### request

```
{
  request_id, actor, requested_capability, operation,
  params,                       // capability payload (redacted in all evidence)
  idempotency_key,              // explicit, persisted before EXECUTE
  expected_sequence,            // monotonic per (actor, capability)
  scope: { max_effects: 1, amount_minor?, note? },
  required_assurance,           // L0..L4, default L1
  authorization_token           // HMAC, bound to the canonical request hash
}
```

### context

```
{
  env, stateDir, registry (CapabilityRegistry), policy (PolicyEngine),
  now?, allowExternalEffects?, authorizationEnvKey?,
  idempotency?, sequence?, ledger?   // injectable stores
}
```

## Stages

1. **REQUEST** — structural validation; compute `request_canonical_sha256`
   (covers actor, capability, operation, params, idempotency-key hash, sequence,
   scope, required assurance).
2. **VERIFY_SCOPE** — the spine authorizes **exactly one** effect per call.
   `scope.max_effects !== 1` ⇒ `DENIED_SCOPE`.
3. **CHECK_PATH** — `registry.resolve(capability)`. No default connector, no
   fuzzy match. Unknown/disabled ⇒ `NO_VERIFIED_PATH`.
4. **DISCOVER_CAPABILITY** — `connector.discover()` (read-only). Observed
   assurance is clamped to the connector's declared ceiling. Below
   `required_assurance` ⇒ `NO_VERIFIED_PATH`. Assurance is **never
   auto-promoted** — the connector re-evidences it every call.
5. **POLICY_CHECK** — `policy.evaluate(...)`. Default `DENY`. Any matching DENY
   wins over any ALLOW ("strictest applicable policy wins"). `policy_hash` is
   recorded so a swapped ruleset is detectable.
6. **AUTHORIZATION** — `verifyAuthorization(token, ...)`. HMAC over the exact
   canonical request hash + idempotency-key hash + actor + capability +
   operation, short TTL, clock-skew bounded. Then the idempotency pre-checks:
   * same key + same request already `SUCCEEDED` ⇒ return the recorded result
     (`replayed: true`), no re-execution;
   * same key + different request ⇒ `REPLAY_REJECTED`;
   * key in `PENDING` / `UNKNOWN_REQUIRES_RECONCILIATION` / `FAILED_FINAL` ⇒
     `REPLAY_REJECTED` (must `reconcile()` first);
   * `expected_sequence <= committed` ⇒ `STALE_STATE_REJECTED`.
7. **claim** — atomic `O_EXCL` idempotency claim; a lost race ⇒ `REPLAY_REJECTED`.
   Capture `pre_state_hash`; append the `EXECUTION_AUTHORIZED` audit row (an
   audit failure here is `INTERNAL_FAIL_CLOSED`).
8. **EXECUTE** — `connector.execute(...)`.
   * throw with `provider_http_status` ⇒ `PROVIDER_FAILURE`, idempotency
     `FAILED_FINAL`;
   * throw without a status (timeout / transport) ⇒ `EXECUTION_UNVERIFIED`,
     idempotency `UNKNOWN_REQUIRES_RECONCILIATION`;
   * no `provider_request_id` in the return ⇒ `EXECUTION_UNVERIFIED`, quarantine.
   Failover to another connector is **not** attempted after a POST may have
   landed.
9. **VERIFY_READBACK** — if `connector.supportsReadback`, call
   `connector.readback(...)`. `verified !== true` or `binding_ok !== true` ⇒
   `READBACK_MISMATCH`, quarantine. Local readback ⇒ assurance capped at L1 and
   `verification_method = LOCAL_STATE_READBACK`; external readback ⇒ up to L4 and
   `AUTHENTICATED_PROVIDER_READBACK`. No readback support ⇒ assurance capped at
   L3, `verification_method = PROVIDER_RECEIPT_ONLY` (classified honestly, never
   "fully verified").
10. **RECEIPT** — assemble the result, compute `result_sha256`.
11. **AUDIT** — append `VERIFIED_EXECUTION_COMMIT` to the hash-chained,
    fsynced ledger (`backend/g-bank-live-v1/receipt-ledger.js`). A failure here
    ⇒ `INTERNAL_FAIL_CLOSED` + quarantine; success is never reported.
12. **COMMIT_STATE** — idempotency `finalize(SUCCEEDED, result)` and advance the
    monotonic sequence. Only now is `canonical_commit_status = COMMITTED`.

## Capability assurance levels

```
L0  declared / configured only
L1  local implementation verified
L2  authenticated external read verified
L3  authenticated external write verified
L4  external write + independent / readback verification
```

The result's `assurance_level_achieved` is `min(discover assurance, connector
ceiling, what THIS execution actually evidenced)`.

## Connectors

A connector is the only thing that touches a real effect. Contract:
`name`, `assurance_ceiling`, `supportsReadback`, `discover()`,
`captureState(req)`, `execute(req)`, `readback(req, exec)`. See
`backend/g-verified-execution-spine/capability-registry.js`.

* **`LocalFileCapability`** (`connectors/local-file.js`) — real, bounded,
  no-network. Appends a record to a JSONL file inside its own root and reads it
  back. Genuine durable effect; local-only ⇒ classified L1. Used to exercise the
  whole pipeline, including readback and recovery, without any external call or
  value movement.
* **`MollieSpineConnector`** (`connectors/mollie-spine-connector.js`) — an
  adapter shim over the pre-existing `MollieLiveAdapter`. Re-asserts
  `requireLiveExecution(env)` **and** `context.allowExternalEffects === true`;
  inert otherwise. `discover()` runs the read-only Mollie preflight (L2).
  `execute()`/`readback()` map to `createPayment`/`getPayment`. Not wired into
  the CLI. Reaching L3/L4 through it requires live credentials and an explicit
  operator opt-in and has **not** been exercised here (see below).

## Recovery

`reconcile({ idempotency_key, provider_request_id? }, context)` handles: *the
provider may have executed, but the local process died before COMMIT_STATE.* It
reads connector state (never re-issues the effect) and returns
`EFFECT_CONFIRMED` / `EFFECT_ABSENT` / `STILL_UNCERTAIN` / `MANUAL_REQUIRED`.
`executeVerified` refuses to re-run a quarantined key until reconciliation has
resolved it.

## Runtime invariants (tested)

```
NO_AUTHORIZATION           => NO_EXECUTION
NO_VERIFIED_PATH           => NO_EXECUTION
FAILED_POLICY              => NO_EXECUTION
FAILED_EXECUTION           => NO_CANONICAL_SUCCESS
FAILED_REQUIRED_READBACK   => NO_CANONICAL_SUCCESS
DUPLICATE_IDEMPOTENCY_KEY  => NO_DUPLICATE_EFFECT
STALE_SEQUENCE             => REJECT
AUDIT_FAILURE              => FAIL_CLOSED
UNKNOWN_PROVIDER_STATE     => UNVERIFIED (never SUCCESS)
SIMULATED_SUCCESS          => NEVER VERIFIED_SUCCESS
```

## Secret handling

`redaction.js` deep-masks sensitive keys (`*token*`, `*secret*`, `*password*`,
`api_key`, `authorization`, `private_key`, `iban`, `pan`, …) and secret-shaped
values (PEM blocks, `Bearer …`, `live_…`, JWTs, AWS keys, GitHub PATs) in
**every** receipt, audit row and returned result. `safeEvidence()` redacts then
hard-asserts nothing survived, and is applied before every ledger append.

## Commands

```bash
node backend/tests/g-verified-execution-spine.test.js      # or: node --test …
node scripts/g-verified-execution-spine.js self-check
G_SPINE_AUTHORIZATION_SECRET=<32+bytes> \
  node scripts/g-verified-execution-spine.js demo-local /tmp/spine-demo
node scripts/g-verified-execution-spine.js verify-audit <audit.jsonl>
```

## Files

```
backend/g-verified-execution-spine/
  states.js                     result states, stages, assurance ladder
  redaction.js                  secret masking + leak assertion
  policy.js                     default-deny, strictest-wins policy engine
  authorization.js              request-generic HMAC authorization
  capability-registry.js        connector contract + registry
  sequence-store.js             monotonic per-stream sequence guard
  spine.js                      executeVerified() + reconcile()
  invariants.js                 machine-testable result invariants
  connectors/local-file.js      real bounded no-network capability
  connectors/mollie-spine-connector.js   shim over the existing Mollie adapter
  index.js
scripts/g-verified-execution-spine.js
backend/tests/g-verified-execution-spine.test.js
```

Reused unchanged: `backend/g-bank-live-v1/canonical.js`,
`idempotency-store.js`, `receipt-ledger.js`, `providers/mollie-live.js`.
