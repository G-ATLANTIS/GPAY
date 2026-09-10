# G-BANK Sovereign Core v2

## Purpose

G-BANK Sovereign Core v2 makes the G-BANK ledger, payment state machine, approval policy, ISO 20022 message generation, idempotency, receipts, prudential controls and reconciliation independent of payment aggregators.

Mollie and TrueLayer are compatibility rails only. They are not the G-BANK source of truth.

## Canonical topology

```text
G-BANK ACCOUNT REGISTRY
        |
G-BANK DOUBLE-ENTRY LEDGER
        |
PAYMENT INSTRUCTION
        |
COMPLIANCE + VOP EVIDENCE
        |
ISO 20022 pacs.008
        |
EXTERNAL SCHEME VALIDATION RECEIPT
        |
RISK POLICY + AUTHORITY QUORUM
        |
EXPLICIT CRYPTOGRAPHIC APPROVAL
        |
SAFEGUARDING + LIQUIDITY + INVARIANT AUDIT
        |
OPERATIONAL RESILIENCE / EMERGENCY FREEZE
        |
ATOMIC IDEMPOTENCY CLAIM
        |
OUTBOUND VALUE HOLD
        |
DIRECT SETTLEMENT TRANSPORT
        |
PROVIDER/CSM READBACK
        |
SETTLED / REJECTED / UNKNOWN
        |
RECONCILIATION
        |
HASH-CHAIN RECEIPTS + LEDGER
```

## Implemented in v2

- sovereign account registry with IBAN checksum validation, write locking and read-only listings
- append-only balanced value ledger with SHA-256 chain verification, fsync and trial-balance snapshots
- canonical payment-instruction hashing
- structured address support for the November 2026 EPC address transition
- ISO 20022 2019 message generation:
  - `pain.001.001.09`
  - `pacs.008.001.08`
- SCT and SCT Inst message modes
- sanctions, AML and Verification-of-Payee evidence gates
- external scheme-validation evidence binding
- deterministic risk policy with per-payment limits, daily velocity, beneficiary blocks and quorum requirements
- authority-set and governance proof binding
- approval bound to:
  - exact prepared payment
  - instruction hash
  - message hash
  - compliance proof
  - scheme-validation receipt
  - source account
  - amount and currency
  - beneficiary binding
  - scheme
  - exact idempotency key
- safeguarding coverage assessment
- intraday/stressed liquidity headroom assessment
- bank-wide invariant auditor
- operational resilience assessment and emergency freeze
- direct settlement adapter contract
- required live connectivity/authentication preflight
- outbound ledger hold before external submission
- no automatic resubmission after ambiguous provider state
- settlement readback and reconciliation
- final value-flow claim only after `SETTLED`
- deterministic rejection release
- hash-chained audit receipts
- no-network safety test suite
- operator CLI with pluggable settlement transport module

## Prudential layer

The safeguarding assessment uses:

```text
required_safeguarded
  = customer_liabilities
  + pending_outbound_holds
  + required_buffer
```

If safeguarded assets are below that requirement, the assessment returns `BLOCK`.

The liquidity assessment uses:

```text
required_liquidity
  = pending_outbound
  + stressed_outflow
  + minimum_buffer
```

If immediately available liquidity is below the requirement, the assessment returns `BLOCK`.

The invariant auditor then requires, at minimum:

- verified ledger hash chain and sequence;
- zero trial-balance total for the currency;
- active safeguarding, suspense and settlement accounts;
- no negative customer balance;
- safeguarding assessment = `PASS`;
- liquidity assessment = `PASS`.

Its resulting audit hash is independently bound into the live-readiness configuration. Environment flags alone cannot manufacture this proof.

## Operational resilience layer

Operational readiness blocks on any of the following:

- ledger integrity not verified;
- receipt-chain integrity not verified;
- checkpoint not verified;
- unresolved settlement uncertainty above the configured policy;
- clock drift above the configured limit;
- emergency freeze active.

The assessment hash is separately bound into live readiness. `UNKNOWN` settlement state is never interpreted as permission to retry or fail over automatically.

## Fail-closed live requirements

All of these must be true before the software readiness gate can report direct-live ready:

```text
G_BANK_ENABLE_LIVE=true
G_BANK_EXTERNAL_ACTIONS_ENABLED=true
G_BANK_DIRECT_SETTLEMENT_ENABLED=true
G_BANK_SIMULATED_LIVE_SUCCESS!=true
G_BANK_GOVERNANCE_REQUIRED=true
G_BANK_SETTLEMENT_AUTHORIZATION_SHA256=<verified external authorization binding>
G_BANK_SOVEREIGN_APPROVAL_SECRET=<minimum 32-byte secret>
G_BANK_SETTLEMENT_TRANSPORT_MODULE=<authorized transport implementation>
G_BANK_LEGAL_AUTHORIZATION_EVIDENCE_SHA256=<verified evidence binding>
G_BANK_SCHEME_PARTICIPATION_EVIDENCE_SHA256=<verified evidence binding>
G_BANK_SETTLEMENT_ACCESS_EVIDENCE_SHA256=<verified evidence binding>
G_BANK_PRODUCTION_IDENTITY_EVIDENCE_SHA256=<verified evidence binding>
G_BANK_PRUDENTIAL_AUDIT_SHA256=<current PASS invariant-audit hash>
G_BANK_OPERATIONAL_RESILIENCE_SHA256=<current PASS resilience-assessment hash>
```

The transport's preflight must independently report:

```text
environment=LIVE
authenticated=true
connected=true
scheme=SCT or SCT_INST
external_receipt_sha256=<verified receipt>
```

The technical readiness result also requires valid governance, prudential and operational PASS evidence. A local environment variable alone therefore cannot make an unverified transport appear live.

## Critical ambiguity rule

A connection failure after submission is treated as potentially having reached the external settlement system.

G-BANK then:

1. does not resubmit automatically;
2. leaves the value in outbound suspense;
3. marks execution `UNKNOWN`;
4. requires readback/reconciliation;
5. never routes the same payment to another provider automatically.

This prevents a failover path from creating a duplicate real payment.

## Ledger booking model

Before external submission:

```text
DEBIT  source account
CREDIT outbound suspense
```

On verified settlement:

```text
DEBIT  outbound suspense
CREDIT settlement-out account
```

On verified rejection:

```text
DEBIT  outbound suspense
CREDIT source account
```

This is an internal conserved-value ledger model. Statutory/financial-reporting general-ledger classification can be layered separately.

## ISO 20022 boundary

Message generation does **not** claim EPC/TARGET validity by itself.

Before execution, G-BANK requires an external scheme-validation receipt cryptographically bound to the exact XML document hash. Production deployments must validate against the applicable scheme rules and production ISO 20022 namespaces/business validation rules.

Current design target: 2025 SCT/SCT Inst rulebooks using the ISO 20022 2019 message version. Unstructured addresses are not relied upon; structured address fields are supported so the core is prepared for the 15 November 2026 EPC change.

## Direct settlement boundary

`backend/g-bank-sovereign-v2/direct-settlement.js` defines the verified transport contract. It deliberately does not pretend that T2, TIPS or another CSM can be reached without real admission, credentials, certificates, network connectivity and provider receipts.

An actual TARGET/TIPS/CSM transport must be supplied through:

```text
G_BANK_SETTLEMENT_TRANSPORT_MODULE=/absolute/path/to/authorized-transport.js
```

The module exports either:

```js
module.exports = { transport }
```

or:

```js
module.exports.createTransport = ({ env }) => transport
```

and the transport implements:

```js
preflight()
submit(payload)
readback(submissionId)
```

## Reality state

```text
G_BANK_SOVEREIGN_CORE_SOFTWARE = IMPLEMENTED_V2
G_BANK_OWN_LEDGER = IMPLEMENTED
G_BANK_OWN_ACCOUNT_REGISTRY = IMPLEMENTED
G_BANK_OWN_PAYMENT_STATE_MACHINE = IMPLEMENTED
G_BANK_OWN_ISO20022_GENERATION = IMPLEMENTED
G_BANK_OWN_APPROVAL_AND_IDEMPOTENCY = IMPLEMENTED
G_BANK_OWN_RISK_GOVERNANCE = IMPLEMENTED
G_BANK_OWN_SAFEGUARDING_ASSESSMENT = IMPLEMENTED
G_BANK_OWN_LIQUIDITY_ASSESSMENT = IMPLEMENTED
G_BANK_OWN_INVARIANT_AUDITOR = IMPLEMENTED
G_BANK_OWN_OPERATIONAL_FREEZE = IMPLEMENTED
G_BANK_OWN_RECONCILIATION = IMPLEMENTED
G_BANK_DIRECT_SETTLEMENT_INTERFACE = IMPLEMENTED
G_BANK_DIRECT_TARGET_TIPS_TRANSPORT = NOT_YET_EXTERNALLY_CONNECTED
G_BANK_EPC_SCHEME_PARTICIPATION = NOT_CLAIMED
G_BANK_DNB_ECB_AUTHORIZATION = NOT_CLAIMED
G_BANK_VALUE_MOVEMENT = DENY_UNTIL_VERIFIED_AUTHORIZED_TRANSPORT
```

## Operator flow

Prepare only (no network):

```bash
node scripts/g-bank-sovereign-v2.js prepare \
  --instruction .secrets/input/payment.json \
  --compliance .secrets/evidence/compliance.json \
  --out .secrets/prepared/payment.json
```

After external scheme validation, generate an approval bound to that exact validation receipt and a fresh idempotency key:

```bash
node scripts/g-bank-sovereign-v2.js approve \
  --prepared .secrets/prepared/payment.json \
  --validation .secrets/evidence/scheme-validation.json \
  --idempotency-key '<fresh-uuid>' \
  --out .secrets/approvals/payment.approval
```

Execution is intentionally impossible until an authorized live transport module and all live gates are configured.

## Promotion rule

Do not label direct settlement `LIVE` until all of the following have real evidence:

- legal/regulatory authorization appropriate to the activity
- scheme/settlement admission where required
- production identity/certificate material
- production network path
- authenticated preflight
- scheme-validation path
- current safeguarding PASS evidence
- current liquidity PASS evidence
- current invariant-audit PASS evidence
- current operational-resilience PASS evidence
- bounded submission
- provider/CSM readback
- reconciliation receipt

No simulated, mocked or locally inferred result can satisfy these conditions.
