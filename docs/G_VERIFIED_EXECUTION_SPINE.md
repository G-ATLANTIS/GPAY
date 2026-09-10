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

Reused: `backend/g-bank-live-v1/canonical.js`, `receipt-ledger.js`,
`providers/mollie-live.js` (unchanged); `idempotency-store.js` (hardened for
crash-safe durability).

---

## Live Mollie routing (G-BANK-CANONICAL-LIVE-ROUTING-P0)

`GBankLiveCore` is **retired** — its constructor throws. Every live Mollie
mutation now goes through `executeVerified()` + `MollieSpineConnector`:

```
scripts/g-bank-live-v1.js  /  backend/routes/mollie.js
        -> buildMollieRequest()            (canonical request)
        -> createAuthorization()           (HMAC bound to the request hash)
        -> executeVerified(request, ctx)
        -> MollieSpineConnector            (discover / execute / readback)
        -> MollieLiveAdapter               (raw provider I/O)
```

`backend/g-verified-execution-spine/gbank-mollie-routing.js` is the shared
wiring (`buildMollieRegistry`, `buildMolliePolicy`, `buildMollieRequest`,
`mollieBindingSha256`) so the CLI and the route construct identically.

### L4 binding

The Mollie connector's `readback()` returns `binding_strength`:

* `STRONG` — payment id **and** live mode **and** amount **and** currency
  **and** `metadata.g_intent_sha256` **and** `metadata.g_destination_binding_sha256`
  all present and matched → spine awards **L4** /
  `AUTHENTICATED_PROVIDER_READBACK`.
* `WEAK` — any of those binding fields missing (e.g. provider did not persist
  metadata) → spine caps at **L3** / `PROVIDER_RECEIPT_ONLY`.
* any positive mismatch (wrong id / amount / currency / hash / non-live mode)
  → `binding_ok:false` → `READBACK_MISMATCH`, quarantined.

Achieved assurance is bounded by the connector's declared ceiling, not by the
read-only discovery level (discovery is the entry gate only).

### Recovery classification

`reconcile()` returns: `EFFECT_CONFIRMED` (read back and bound to this
execution — recovers the original outcome, never re-issues), `EFFECT_ABSENT`
(provider definitively lacks it — a fresh attempt is allowed only after an
explicit safe transition), `STILL_UNCERTAIN` / `MANUAL_REQUIRED` (cannot prove
either way — retry is **not** permitted). Mollie without a provider payment id
is `MANUAL_REQUIRED`.

### Execution truth

`getExecutionTruth(idempotencyKey, ctx)` — the single authoritative answer
(authorized / execution_attempted / provider_accepted / externally_verified /
canonical_success / retry_safe), derived **only** from the spine idempotency
record + hash-chained audit ledger. Legacy `G_*.json` files are not consulted.

### Durability

`backend/g-bank-live-v1/durable-write.js`: `durableCreateFileSync` /
`durableReplaceFileSync` = temp write → `fsync(file)` → atomic `rename` →
`fsync(dir)`. Used by `IdempotencyStore.claim/finalize` and
`SequenceStore.commit` so a completed state transition survives a crash.

### Static bypass guard

`scripts/ci/check-spine-bypass.js` (`npm run guard:spine-bypass`) fails if
non-allowlisted code reaches a live provider mutation outside the spine. See
`docs/G_BANK_MUTATION_PATH_INVENTORY.md` for the full path inventory.

### Fail-closed non-Mollie routes

`backend/routes/pulsepay.js` is **DENY by default** — 403 unless an explicit
`G_BANK_ALLOW_UNSPINED_PULSEPAY=I_ACCEPT_UNSPINED_EXECUTION` env acknowledgement
is set. `backend/routes/webhook.js` is a 501 stub.

---

## Live TrueLayer routing (TRUELAYER-CANONICAL-SPINE-ROUTING-P0)

`backend/routes/openbanking.js` `POST /create-payment` is now spine-routed and
the `G_BANK_ALLOW_UNSPINED_TRUELAYER` escape hatch is **deleted**.

```
POST /api/open-banking/create-payment
  -> operatorAuthorizationMiddleware (X-G-Bank-Operator-Authorization)
  -> assertConfigured() + assertPaymentInput()
  -> assertLiveApproval()          (per-payment X-G-Bank-Approval HMAC, live only)
  -> buildTrueLayerRequest()       (canonical request; PII kept out / hashed)
  -> createAuthorization()         (spine HMAC bound to the request hash)
  -> executeVerified(request, ctx)
  -> TrueLayerSpineConnector       (discover / execute / readback)
  -> TrueLayerLiveAdapter          (OAuth + ES512 detached JWS + node:https)
  -> TrueLayer API
```

`backend/g-verified-execution-spine/gbank-truelayer-routing.js` is the shared
wiring (`buildTrueLayerRegistry`, `buildTrueLayerPolicy`, `buildTrueLayerRequest`,
`truelayerBindingSha256`).

### Canonical binding & PII

`buildTrueLayerRequest` puts only safe values in `params`; beneficiary IBAN,
holder name and payer PII (`full_name`, `email`, `phone`, `date_of_birth`,
`address_line*`, `zip`) sit under keys that `redaction.js` masks, so they are
`[REDACTED]` in every audit row / result / idempotency record while the
connector still receives real values to build the provider body.
`destination_binding` embeds `sha256(iban):sha256(reference)`, never raw PII.
The canonical request hash (`g_intent_sha256`) and a `sha256` of the
destination binding are written into TrueLayer payment `metadata`.

### Assurance

* `discover()` = OAuth token (scope `payments`) + a signed `POST /test-signature`
  returning 204 → **L2**. Sub-L2 (no token / signature rejected) → `NO_VERIFIED_PATH`.
* `readback()` binding_strength **STRONG** (→ L4 / `AUTHENTICATED_PROVIDER_READBACK`)
  requires: payment id + environment (`live`/`sandbox`) + amount + currency +
  beneficiary IBAN + beneficiary reference + `metadata.g_intent_sha256` +
  `metadata.g_destination_binding_sha256`, all present and matched.
* Missing binding evidence → **WEAK** → capped at **L3** / `PROVIDER_RECEIPT_ONLY`.
* Any positive mismatch (id / amount / currency / iban / reference / wrong
  environment) → `READBACK_MISMATCH`, quarantined.

### Idempotency ↔ provider

The local idempotency key is sent as TrueLayer's `Idempotency-Key` header on
`POST /v3/payments`; the returned payment id is bound to the canonical request
hash via payment `metadata`. `getExecutionTruth()` binds all three.

### Reconciliation

`reconcile()` for TrueLayer: with an operator-supplied payment id it does a
`GET /v3/payments/:id` and confirms on the non-PII triplet (payment id +
environment + `metadata.g_intent_sha256` == canonical request hash) →
`EFFECT_CONFIRMED` (recovers the original outcome, never re-issues). A
definitive `NOT_FOUND` → `EFFECT_ABSENT`. No payment id, or provider
unreachable → `MANUAL_REQUIRED` / `STILL_UNCERTAIN`; **retry is not permitted.**
Redacted reconcile params cannot re-check amount/IBAN, which is why the
canonical-hash-in-metadata binding is the confirmation basis.

### Beneficiary allowlist

`G_BANK_ALLOWED_BENEFICIARY_IBANS` is enforced in `TrueLayerSpineConnector.execute()`
(LIVE only) as a pre-provider refusal (`PROVIDER_FAILURE` / `FAILED_FINAL`, no
call made) and, fast-path, in the route.

## Phase 10 — webhooks cannot forge canonical success

`openbanking.js` `POST /webhook` already verifies the `Tl-Signature` (JWKS +
detached-JWS), the timestamp/replay window, and classifies the event as
`observation_only: true`, `value_moved_by_handler: false`. It writes to the
legacy webhook-receipt store only. `getExecutionTruth()` and the spine's
`canonical_commit_status` are derived **exclusively** from the spine idempotency
record + hash-chained audit ledger — a webhook receipt has no path to
`VERIFIED_SUCCESS`. (Tested: `webhook receipt cannot forge canonical success`.)

## Phase 11 — legacy `scripts/g-payment-*` gate semantics

The parallel gate lineage is **superseded**, not deleted; it stays as a
diagnostic evidence producer that does not determine execution truth.

| legacy control | absorbed into |
|---|---|
| amount cap (`G_BANK_MAX_PAYMENT_EUR`) | spine policy `max_amount_minor` (`buildTrueLayerPolicy`) |
| beneficiary IBAN allowlist | `TrueLayerSpineConnector.execute()` + route pre-check |
| OAuth `payments` scope + authenticated + signature proof (`g-payment-live-oauth-proof-capture`, `…-provider-entitlement-gate`) | connector `discover()` → L2 entry gate; sub-L2 ⇒ `NO_VERIFIED_PATH` |
| per-payment human approval (`assertLiveApproval` / `X-G-Bank-Approval`) | kept in route + spine `createAuthorization` bound to the request hash |
| single-use authorization, freshness window, replay-deny, canonical hashing, default-deny reason lists (`g-payment-rail-eligibility-router`, `…-execution-gate`, `…-provider-request-envelope`, `…-materialization-preflight`) | spine: authorization TTL + one-request binding, monotonic `SequenceStore`, `IdempotencyStore` replay-deny, `requestCanonicalSha256`, `PolicyEngine` default-deny |

Physically folding each `g-payment-*` script into the connector remains a
follow-up cleanup; their load-bearing semantics are already enforced by the
spine.

---

## TrueLayer sandbox execution lane + E2E verification (TRUELAYER-SANDBOX-E2E-VERIFICATION-P0)

### Sandbox execution lane

`TrueLayerSpineConnector._assertExecutable()`:

* `TRUELAYER_ENV=live` → unchanged strict `requireLiveExecution()` gate.
* `TRUELAYER_ENV=sandbox` (hits `*.truelayer-sandbox.com`, no real money) → a
  **separate, off-by-default** permission: `G_BANK_ENABLE_SANDBOX_EXTERNAL=true`
  (the legacy `G_BANK_ENABLE_LIVE=true` + `G_BANK_EXTERNAL_ACTIONS_ENABLED=true`
  combo is still accepted for back-compat). This lets a sandbox proof run with
  `G_BANK_ENABLE_LIVE=false`. The sandbox flag never enables production —
  `TRUELAYER_ENV=live` still requires the full live gate.

### E2E harness

`scripts/verify-truelayer-sandbox-e2e.js` (`npm run verify:truelayer-sandbox-e2e`)
and `backend/tests/g-truelayer-sandbox-e2e.test.js`:

* **Phase 0 hard boundary** — aborts with **no provider call** unless
  `TRUELAYER_ENV=sandbox`, resolved hosts are `*.truelayer-sandbox.com`, and
  `G_BANK_ENABLE_LIVE!=true`. No silent correction / fallback.
* **Phase 1** — redacted config preflight (presence booleans + sha256 of
  kid/client_id, P-521 key parse check, return-URI shape). No secret values.
* **Phase 2** — real `connector.discover()` (OAuth `client_credentials` scope
  `payments` + signed `POST /test-signature`).
* **Phase 4** — exactly one sandbox payment via `executeVerified()` (never the
  adapter directly).
* **Phase 3/5/8** — independent `GET /v3/payments/:id` readback + a schema
  probe of the actual response key paths; binding classified STRONG / WEAK /
  MISMATCH; the previously-unverified assumptions (A–E) resolved to
  VERIFIED / NOT_EXPOSED / UNVERIFIED from the real response.
* **Phase 6** — replay the same request → asserts no second provider effect.
* **Phase 7** — `reconcile()` → EFFECT_CONFIRMED; a nonexistent-id reconcile
  records the classification TrueLayer actually permits.
* **Phase 11** — one `g-truelayer-sandbox-e2e-evidence-v1` receipt under
  `.secrets/evidence/` (git-ignored, 0600, no secrets/PII).

The opt-in integration test is **skipped** unless
`G_TRUELAYER_RUN_SANDBOX_E2E=true`; normal CI runs only the always-on guard unit
tests and never needs provider credentials.
