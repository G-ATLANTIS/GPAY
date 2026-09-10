# G-BANK Sovereign Core v2

## Purpose

G-BANK Sovereign Core v2 makes the G-BANK ledger, customer-account state, inbound/outbound payment state machines, approval policy, ISO 20022 generation, idempotency, receipts, treasury controls, prudential controls and reconciliation independent of payment aggregators.

Mollie and TrueLayer are compatibility rails only. They are not the G-BANK source of truth.

## Canonical topology

```text
                         G-BANK SOVEREIGN CORE
                                   |
                    ACCOUNT REGISTRY / LIFECYCLE
                                   |
                         DOUBLE-ENTRY LEDGER
                         /                 \
                        /                   \
               OUTBOUND SCT/SCT INST      INBOUND SCT/SCT INST
                       |                         |
             COMPLIANCE / VOP             VERIFIED EXTERNAL EVENT
                       |                         |
                 ISO 20022                  INBOUND SUSPENSE
                       |                         |
           SCHEME VALIDATION                   RELEASE PROOF
                       |                         |
             RISK / GOVERNANCE              CUSTOMER AVAILABLE
                       |                         |
                  APPROVAL                  BALANCE / STATEMENT
                       |                         |
          PRUDENTIAL / TREASURY                 |
                       |                         |
            EXTERNAL/HSM SIGNING                |
                       |                         |
          TECHNICAL PROMOTION CERT               |
                       |                         |
             DIRECT SETTLEMENT                   |
                       \                         /
                        \                       /
                     EXTERNAL STATEMENT RECONCILIATION
                                   |
                         DUAL-SIDED EOD CLOSE
                                   |
                         HASH-CHAIN STATE ROOT
```

## Implemented in v2

- sovereign account registry with IBAN checksum validation, write locking and controlled status transitions
- cross-module account-operation mutex for lifecycle/inbound serialization
- append-only balanced ledger with SHA-256 chain verification, fsync, trial balance and verified read-only records
- customer-account lifecycle: `ACTIVE -> SUSPENDED -> ACTIVE/CLOSED`
- close requires verified ledger, zero available balance and no `CLAIMED/PENDING` inbound funds
- pending/available customer balance view bound to ledger and inbound-state roots
- hash-bound customer account statements with opening/closing/running balances
- inbound SCT/SCT Inst processing from hash-verified external settlement evidence
- deterministic duplicate detection and crash recovery for inbound booking
- inbound settlement first books to suspense; separate fresh release evidence is required before customer availability
- return/recall artifacts are `NOT_SUBMITTED` and never move value by themselves
- incoming external-statement completeness reconciliation
- canonical outbound payment-instruction hashing
- ISO 20022 2019 `pain.001.001.09` and `pacs.008.001.08` generation
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
- external/HSM-style signature verification with trusted public-key binding
- short-lived technical promotion certificate binding all readiness evidence
- direct settlement adapter contract
- outbound ledger hold before external submission
- no automatic resubmission after ambiguous provider state
- settlement readback and reconciliation
- hash-verified outbound settlement-statement reconciliation
- inbound state included in the canonical checkpoint root
- dual-sided EOD close requiring outbound and inbound reconciliation PASS
- append-only end-of-day close proof store
- hash-chained audit receipts
- no-network safety test suite
- operator CLI with pluggable settlement transport module

## Inbound payment model

G-BANK does not credit a customer merely because an untrusted message says money arrived. The inbound processor requires a hash-verified external settlement event with `SETTLED`, a supported scheme, valid currency/IBAN binding, external receipt hash and settlement business date.

First booking:

```text
DEBIT  inbound settlement account
CREDIT inbound suspense account
```

State becomes `PENDING`. A second, fresh and hash-bound release proof must match the exact inbound event, account, amount and currency before funds become available:

```text
DEBIT  inbound suspense account
CREDIT customer account
```

Duplicate events reuse the same deterministic transaction ID. A crash after ledger booking but before state transition is recoverable by verifying the existing ledger record; it is never booked twice.

## Customer-account lifecycle

Lifecycle and inbound posting share a cross-module account-operation lock. This prevents an account close/suspend and an inbound availability transition from silently crossing each other.

A customer account may be closed only from `SUSPENDED`, with:

```text
ledger integrity = VERIFIED
available balance = 0
pending/claimed inbound count = 0
```

A closed or suspended customer cannot receive an availability credit. Account status transitions require a 64-hex-character SHA-256 evidence binding and are stored in the registry hash root.

## Account balances and statements

`account-balance-view.js` separates:

```text
available_balance_minor
pending_inbound_minor
projected_balance_minor
```

The view binds both the ledger head and inbound-state head.

`account-statements.js` builds read-only statements directly from verified ledger records and binds the output to the current ledger head. It includes opening balance, closing balance, per-entry delta and running balance.

## Inbound statement completeness

At EOD an external inbound settlement statement is hash-verified and compared with all G-BANK inbound records for the same business date and currency.

Reconciliation blocks on:

- external incoming settlement missing from G-BANK;
- G-BANK inbound record missing from the external statement;
- amount mismatch;
- duplicate inbound IDs;
- statement tampering;
- mixed currency;
- internal inbound left in `CLAIMED` rather than `PENDING/AVAILABLE`.

No mismatch is auto-corrected and no return or compensating payment is automatically created.

## Prudential and treasury layer

Safeguarding requires protected customer liabilities and configured buffer to be covered. Liquidity requires immediately available liquidity to cover pending outbound flows, stressed outflow and minimum buffer.

Treasury position is assessed against a hash-verified external settlement-liquidity snapshot. The snapshot binds currency, available amount, settlement system, settlement account identity and observation time. A random hash or locally asserted balance cannot satisfy the treasury evidence check.

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

Negative headroom returns `BLOCK`. `DIRECT_LIVE_READY` also requires a current PASS treasury assessment whose full hash is recomputed and matches the configured binding.

## External/HSM signing boundary

`external-signing.js` deliberately contains no private-key storage or signing implementation. G-BANK creates a canonical signing request bound to the prepared payment, exact ISO 20022 message hash and settlement-authorization evidence.

An external signer/HSM response is accepted only when the signing-request hash and message hash match, the public-key SPKI hash is trusted, the signature is cryptographically valid, the signing evidence is fresh and a signer receipt hash is present.

Supported verification algorithms are Ed25519, ECDSA-SHA256 and RSA-SHA256. The resulting proof/envelope does not submit a payment.

## Technical promotion certificate

`promotion-certificate.js` creates a short-lived, hash-bound technical promotion certificate only after the software readiness snapshot is `DIRECT_LIVE_READY`.

It binds readiness, checkpoint root, governance, signing-key identity, legal/scheme/settlement/production-identity evidence, transport receipt, prudential audit, resilience and treasury assessment.

It always contains:

```text
grants_external_rights = false
permits_value_movement_by_itself = false
requires_runtime_reverification = true
```

It therefore cannot create a licence, scheme membership, TARGET/TIPS access or payment authority.

## End-of-day close

A business date can become `CLOSED` only when all of these are valid and hash-bound:

```text
state checkpoint (including inbound state)
invariant audit = PASS
safeguarding = PASS
liquidity = PASS
treasury = PASS
operational resilience = PASS
outbound settlement reconciliation = PASS
inbound settlement reconciliation = PASS
```

The EOD root binds both external statement hashes and both reconciliation hashes. `EndOfDayStore` is append-only per business date; replaying the exact same root is idempotent and a different second root is denied.

## Fail-closed live requirements

A technical `DIRECT_LIVE_READY` result still requires real external authorization and transport evidence, including:

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

The settlement transport preflight must independently establish LIVE, authenticated and connected status, a supported SCT/SCT Inst scheme and an external receipt hash. Environment variables alone cannot manufacture valid readiness.

## Reality state

```text
G_BANK_SOVEREIGN_CORE_SOFTWARE = IMPLEMENTED_V2
G_BANK_OWN_LEDGER = IMPLEMENTED
G_BANK_OWN_ACCOUNT_REGISTRY = IMPLEMENTED
G_BANK_OWN_ACCOUNT_LIFECYCLE = IMPLEMENTED
G_BANK_OWN_INBOUND_PAYMENT_STATE = IMPLEMENTED
G_BANK_OWN_PENDING_AVAILABLE_BALANCES = IMPLEMENTED
G_BANK_OWN_ACCOUNT_STATEMENTS = IMPLEMENTED
G_BANK_OWN_INBOUND_DUPLICATE_RECOVERY = IMPLEMENTED
G_BANK_OWN_INBOUND_STATEMENT_RECONCILIATION = IMPLEMENTED
G_BANK_OWN_PAYMENT_STATE_MACHINE = IMPLEMENTED
G_BANK_OWN_ISO20022_GENERATION = IMPLEMENTED
G_BANK_OWN_APPROVAL_AND_IDEMPOTENCY = IMPLEMENTED
G_BANK_OWN_RISK_GOVERNANCE = IMPLEMENTED
G_BANK_OWN_SAFEGUARDING_ASSESSMENT = IMPLEMENTED
G_BANK_OWN_LIQUIDITY_ASSESSMENT = IMPLEMENTED
G_BANK_OWN_TREASURY_POSITION = IMPLEMENTED
G_BANK_OWN_INVARIANT_AUDITOR = IMPLEMENTED
G_BANK_OWN_OPERATIONAL_FREEZE = IMPLEMENTED
G_BANK_OWN_EXTERNAL_SIGNING_VERIFICATION = IMPLEMENTED
G_BANK_OWN_TECHNICAL_PROMOTION_CERTIFICATE = IMPLEMENTED
G_BANK_OWN_OUTBOUND_STATEMENT_RECONCILIATION = IMPLEMENTED
G_BANK_OWN_DUAL_SIDED_END_OF_DAY_CLOSE = IMPLEMENTED
G_BANK_DIRECT_SETTLEMENT_INTERFACE = IMPLEMENTED
G_BANK_DIRECT_TARGET_TIPS_TRANSPORT = NOT_YET_EXTERNALLY_CONNECTED
G_BANK_EPC_SCHEME_PARTICIPATION = NOT_CLAIMED
G_BANK_DNB_ECB_AUTHORIZATION = NOT_CLAIMED
G_BANK_VALUE_MOVEMENT = DENY_UNTIL_VERIFIED_AUTHORIZED_TRANSPORT
```

## Promotion rule

Do not label direct settlement `LIVE` until legal/regulatory authorization, scheme/settlement admission, production identity/certificate material, production network path, authenticated transport preflight, scheme validation, current governance/prudential/treasury/resilience PASS evidence, trusted external-signing proof, a bounded authorized submission, provider/CSM readback and inbound/outbound settlement reconciliation receipts all exist as real external evidence.

No simulated, mocked or locally inferred result can satisfy these conditions.
