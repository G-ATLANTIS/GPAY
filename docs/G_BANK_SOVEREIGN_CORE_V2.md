# G-BANK Sovereign Core v2

## Purpose

G-BANK Sovereign Core v2 makes the G-BANK ledger, payment state machine, approval policy, ISO 20022 message generation, idempotency, receipts, treasury controls, prudential controls and reconciliation independent of payment aggregators.

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
TREASURY / PREFUNDING / SETTLEMENT HEADROOM
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
EXTERNAL STATEMENT RECONCILIATION
        |
END-OF-DAY CLOSE ROOT
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
- approval bound to the exact prepared payment, validation receipt and idempotency key
- safeguarding coverage assessment
- intraday/stressed liquidity headroom assessment
- evidence-bound treasury position and prefunding headroom
- bank-wide invariant auditor
- operational resilience assessment and emergency freeze
- direct settlement adapter contract
- outbound ledger hold before external submission
- no automatic resubmission after ambiguous provider state
- settlement readback and reconciliation
- hash-verified external settlement-statement reconciliation
- append-only end-of-day close proof store
- hash-chained audit receipts
- no-network safety test suite
- operator CLI with pluggable settlement transport module

## Prudential and treasury layer

Safeguarding requires protected customer liabilities and configured buffer to be covered. Liquidity requires immediately available liquidity to cover pending outbound flows, stressed outflow and minimum buffer.

Treasury position is independently assessed against a **hash-verified external settlement-liquidity snapshot**. The snapshot must bind currency, available amount, settlement system, settlement account identity and observation time. A random hash or locally asserted balance cannot satisfy the treasury evidence check.

Treasury headroom is calculated as:

```text
required_settlement_liquidity
  = pending_outbound_holds
  + minimum_prefunding
  + reserve_buffer
  + stressed_outflow

settlement_headroom
  = verified_external_settlement_liquidity
  - required_settlement_liquidity
```

A negative headroom returns `BLOCK`.

The invariant auditor requires ledger integrity, zero trial-balance total, mandatory system accounts, non-negative customer balances, safeguarding PASS and liquidity PASS.

## Settlement statement reconciliation

At end of day, externally settled entries are reconciled against G-BANK's own `SOVEREIGN_SETTLEMENT_VERIFIED` receipts using the settlement `submission_id`, amount and currency.

The external statement must be hash-verified and must use one currency consistently. Reconciliation blocks on duplicate internal settlement receipts, missing external settlements, unexpected external settlements, amount mismatches, statement tampering or statement-entry currency mismatch.

No mismatch is auto-corrected and no compensating payment is generated automatically.

## End-of-day close

A business date can become `CLOSED` only when all of these are valid and hash-bound:

```text
state checkpoint
invariant audit = PASS
safeguarding = PASS
liquidity = PASS
treasury = PASS
operational resilience = PASS
settlement reconciliation = PASS
```

The resulting EOD close contains the state root and all control-proof hashes. `EndOfDayStore` is append-only per business date: replaying the same close root is idempotent, while attempting to close the same date with a different root is denied.

## Operational resilience layer

Operational readiness blocks on ledger or receipt-chain integrity failure, checkpoint failure, unresolved settlement uncertainty above policy, excessive clock drift, or emergency freeze.

`UNKNOWN` settlement state is never interpreted as permission to retry or fail over automatically.

## Fail-closed live requirements

All software and external gates must pass before the technical readiness gate can report `DIRECT_LIVE_READY`, including:

```text
G_BANK_ENABLE_LIVE=true
G_BANK_EXTERNAL_ACTIONS_ENABLED=true
G_BANK_DIRECT_SETTLEMENT_ENABLED=true
G_BANK_SIMULATED_LIVE_SUCCESS!=true
G_BANK_GOVERNANCE_REQUIRED=true
G_BANK_SETTLEMENT_AUTHORIZATION_SHA256=<verified external authorization binding>
G_BANK_LEGAL_AUTHORIZATION_EVIDENCE_SHA256=<verified evidence binding>
G_BANK_SCHEME_PARTICIPATION_EVIDENCE_SHA256=<verified evidence binding>
G_BANK_SETTLEMENT_ACCESS_EVIDENCE_SHA256=<verified evidence binding>
G_BANK_PRODUCTION_IDENTITY_EVIDENCE_SHA256=<verified evidence binding>
G_BANK_PRUDENTIAL_AUDIT_SHA256=<current PASS invariant-audit hash>
G_BANK_OPERATIONAL_RESILIENCE_SHA256=<current PASS resilience-assessment hash>
G_BANK_TREASURY_ASSESSMENT_SHA256=<current PASS treasury-assessment hash>
```

The transport preflight must independently report LIVE, authenticated and connected status, supported SCT/SCT Inst scheme and an external receipt hash.

Environment variables alone cannot manufacture a valid readiness state because the supplied prudential, operational and treasury assessments are themselves hash-recomputed and bound.

## Critical ambiguity rule

A connection failure after submission is treated as potentially having reached the external settlement system. G-BANK does not auto-resubmit, keeps value in outbound suspense, marks the execution `UNKNOWN`, and requires reconciliation.

## Direct settlement boundary

`backend/g-bank-sovereign-v2/direct-settlement.js` defines the verified transport contract. It deliberately does not claim T2, TIPS or CSM access without actual authorization, production identity/certificates, connectivity and external receipts.

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
G_BANK_OWN_TREASURY_POSITION = IMPLEMENTED
G_BANK_OWN_INVARIANT_AUDITOR = IMPLEMENTED
G_BANK_OWN_OPERATIONAL_FREEZE = IMPLEMENTED
G_BANK_OWN_SETTLEMENT_STATEMENT_RECONCILIATION = IMPLEMENTED
G_BANK_OWN_END_OF_DAY_CLOSE = IMPLEMENTED
G_BANK_OWN_RECONCILIATION = IMPLEMENTED
G_BANK_DIRECT_SETTLEMENT_INTERFACE = IMPLEMENTED
G_BANK_DIRECT_TARGET_TIPS_TRANSPORT = NOT_YET_EXTERNALLY_CONNECTED
G_BANK_EPC_SCHEME_PARTICIPATION = NOT_CLAIMED
G_BANK_DNB_ECB_AUTHORIZATION = NOT_CLAIMED
G_BANK_VALUE_MOVEMENT = DENY_UNTIL_VERIFIED_AUTHORIZED_TRANSPORT
```

## Promotion rule

Do not label direct settlement `LIVE` until legal/regulatory authorization, scheme/settlement admission, production identity/certificate material, production network path, authenticated transport preflight, scheme-validation path, current governance/prudential/treasury/resilience PASS evidence, bounded submission, provider/CSM readback and reconciliation receipts all exist as real external evidence.

No simulated, mocked or locally inferred result can satisfy these conditions.
