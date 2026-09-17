# ATLAS Payment Fabric v2 — production rebuild plan

Status: DESIGN_LOCKED / LIVE_VALUE_TRANSFER_DISABLED
Date: 2026-09-17
Owner: Gijs

## Objective
Build one canonical EUR payment path that can take a user-approved ATLAS payment intent through provider entitlement, beneficiary verification, bank authorisation/SCA, provider submission, settlement proof and reconciliation.

The system MUST fail closed. “Guaranteed” means deterministic safety and state integrity inside ATLAS; external settlement cannot be guaranteed because provider entitlement, bank limits, bank availability, SCA and scheme processing are external dependencies.

## Canonical flow
1. INTENT_CAPTURED
2. OWNER_APPROVED
3. PROVIDER_ENTITLEMENT_VERIFIED
4. BENEFICIARY_VERIFIED
5. BANK_AND_AMOUNT_ELIGIBLE
6. PAYMENT_CREATED_AWAITING_SCA
7. USER_SCA_AUTHORIZED
8. PROVIDER_SUBMITTED
9. SETTLED
10. RECONCILED

Any failed or ambiguous gate -> BLOCKED. No automatic override.
## Phase 0 — security baseline
- Keep `G_BANK_ENABLE_LIVE=false` until all acceptance gates pass.
- Store production secrets at mode 0600 and runtime directories at 0700.
- Never log access tokens, client secrets, private keys, IBAN plaintext or bank credentials.
- Bind every artifact with SHA-256 and use atomic single-use writes.
- Use idempotency keys for provider creation calls and reject replay.
- Keep payment creation and payment authorisation as separate states.

Acceptance:
- secret permissions verified;
- live gate false;
- no plaintext secret appears in logs or receipts;
- replay and tamper tests pass.

## Phase 1 — provider entitlement
Primary rail: TrueLayer Payments API v3.
- Capture a fresh live OAuth proof with `client_credentials` and scope `payments`.
- Require HTTP success, bearer token, returned `payments` scope, client/app binding and fresh provider evidence.
- Current blocker `invalid_scope` must become a successful entitlement proof before progression.

Acceptance:
- `PROVIDER_ENTITLEMENT_VERIFIED=true`;
- no payment endpoint called during proof;
- proof age <= 5 minutes;
- production client/app bindings match configured credentials.
## Phase 2 — beneficiary and invoice binding
- Payment intent contains exact amount, currency, dealer legal name, invoice/reference and beneficiary IBAN.
- IBAN checksum is mandatory.
- Bind invoice hash + beneficiary name + IBAN hash + amount into the immutable intent.
- Add account-holder/Verification-of-Payee check when provider scope is available.
- Never override a no-match or unresolved beneficiary result automatically.
- Require independent seller/invoice validation before a high-value payment.

Acceptance:
- beneficiary identity is verified or manually escalated;
- invoice and payment intent hashes match;
- no beneficiary field can change after owner approval.

## Phase 3 — rail and scheme routing
- Replace the current `ELIGIBLE_WITHOUT_NEW_SCA` assumption.
- Treat `SCA_REQUIRED` as the normal safe state for a new bank payment.
- TrueLayer external-account EUR payment is the primary rail.
- For amount >= EUR 100,000, force SEPA Credit compatible routing; never use `instant_only`.
- For smaller amounts use `instant_preferred` unless provider evidence says otherwise.
- Query/verify selected bank capability and applicable amount limit before payment creation.

Acceptance:
- EUR 294,900 routes to SEPA Credit-compatible mode;
- SCA requirement does not cause a false rejection;
- unknown bank limit -> BLOCKED, never assumed.
## Phase 4 — owner approval and execution authorization
- Replace bare chat `YES` as the sole approval with a structured approval receipt.
- Approval binds intent ID, amount, currency, dealer name, beneficiary IBAN hash, invoice hash and expiry.
- Require a second short-lived execution authorization immediately before provider payment creation.
- The provider creation authorization is single-use and cannot authorize a changed intent.

Acceptance:
- altered amount/IBAN/reference invalidates approval;
- expired or replayed approval is denied;
- provider create call is impossible without both owner approval and execution authorization.

## Phase 5 — provider materialization
- Load provider credentials only in the execution process.
- Build a TrueLayer `/v3/payments` payload with EUR, `bank_transfer`, `external_account`, dealer name, IBAN and reference.
- Include a unique idempotency key and valid `Tl-Signature`.
- Never persist the bearer access token.
- Persist only safe hashes, provider request IDs and response identifiers.

Acceptance:
- dry-run payload schema validates;
- signing-key/KID pair passes provider signature test;
- duplicate execution returns the same idempotent result or is denied;
- credential values never enter artifacts.
## Phase 6 — SCA / bank authorisation
- Payment creation produces a payment ID/resource token or hosted-page URL; this is NOT settlement.
- Present the bank authorisation journey to the owner.
- Only the owner completes bank/SCA authentication.
- ATLAS never stores bank login credentials or OTPs.
- Return handling binds to the exact payment ID and intent.

Acceptance:
- payment cannot progress to `USER_SCA_AUTHORIZED` without provider readback/webhook evidence;
- cancelled/failed/unknown SCA is fail-closed;
- return URI is HTTPS and allowlisted.

## Phase 7 — status, webhook and reconciliation
- Verify webhook signature before state transition.
- Correlate provider payment ID, intent hash, amount, currency and beneficiary binding.
- Use GET payment readback as independent status confirmation.
- `SETTLED` requires provider evidence; `RECONCILED` requires final settlement/confirmation evidence.
- UNKNOWN is a first-class state: never retry value movement blindly.

Acceptance:
- forged webhook cannot move state;
- duplicate webhook is idempotent;
- conflicting webhook/readback -> UNKNOWN/BLOCKED;
- settled amount and currency must exactly match intent.
## Phase 8 — high-value EUR policy
For the Mercedes target amount, EUR 294,900:
- production provider entitlement must be verified;
- bank-specific open-banking limit must explicitly cover the amount;
- dealer beneficiary must be verified and bound to the invoice;
- ATLAS policy limit must be changed only after these checks, not before;
- require explicit high-value owner approval close to execution;
- require SCA at the bank;
- route to SEPA Credit-compatible scheme, not `instant_only`;
- monitor until final provider settlement evidence exists.

No code may split the payment into smaller transactions to evade a bank/provider/policy limit.

## Phase 9 — fallback strategy
- Primary: TrueLayer Payments v3 external-account payment.
- Secondary: bunq only if a real production bunq account/API session and `payment.execute` are independently verified.
- Direct SEPA rail remains disabled unless ATLAS has lawful PSP/EMI participation, settlement access and verified signing/HSM infrastructure.
- If no automated rail satisfies all gates, return `MANUAL_BANK_AUTHORIZATION_REQUIRED`; never fake success.

## Go-live definition
`ATLAS_PAYMENT_LIVE_READY=true` only when all phases 0-9 pass with fresh evidence. A live switch is a separate deliberate action after the readiness report. The first production transaction should be a controlled low-value validation transaction to an owned/verified beneficiary before any high-value dealer payment.