# G-BANK Customer Control v2

## Purpose

This layer gives G-BANK a provider-independent customer/onboarding control plane without claiming regulatory approval, identity-provider authority, or IBAN-issuance rights.

## Data minimization

The sovereign customer registry stores a pseudonymous `subject_binding_sha256`, customer ID, coarse customer type/jurisdiction, status and evidence hashes. It does not require raw names, dates of birth, identity-document images or credential secrets in the ledger/customer state chain.

Raw verification data remains outside this control plane and is referenced only through verified evidence/receipt hashes.

## Customer state

```text
PROSPECT
   |
 REVIEW
  /   \
ACTIVE REJECTED
  |
SUSPENDED
 /      \
ACTIVE  CLOSED
```

Every transition is append-only, sequence-checked and SHA-256 hash-chained. The subject binding cannot change after genesis.

## Onboarding gate

Activation requires a hash-verified onboarding bundle bound to the same subject containing:

- external identity verification = `VERIFIED`;
- sanctions screening = `CLEAR`;
- PEP assessment = `CLEAR` or separately completed enhanced due diligence;
- explicit operator decision = `APPROVE`;
- provider/operator receipt bindings and freshness checks.

The resulting proof always declares:

```text
technical_gate_only = true
grants_regulatory_authorization = false
```

The rules are software safety gates. They do not claim that these checks alone satisfy every legal/customer-due-diligence requirement for a production payment institution.

## Account provisioning

Only a customer whose current sovereign status is `ACTIVE` can be provisioned a customer account.

G-BANK can create an internal account with no IBAN. If an IBAN is attached, the provisioner requires a fresh, fully hash-verified external assignment artifact bound to the exact subject and IBAN, including an external issuer and receipt hash.

The provisioning proof always declares:

```text
local_iban_issuance_performed = false
grants_iban_issuance_authority = false
```

Therefore G-BANK never treats local IBAN syntax/checksum generation as legal/operational issuance.

## Customer suspension propagation

Customer suspension is fail-closed and ordered:

```text
1. acquire account-operation mutex
2. suspend every ACTIVE account linked to the customer
3. verify no linked ACTIVE account remains
4. transition customer ACTIVE -> SUSPENDED
```

If the process fails halfway, the safe failure mode is excess restriction: accounts may already be suspended while the customer record is still ACTIVE. Re-running the operation completes the customer transition without re-enabling an account.

Reactivation uses the opposite safe ordering: customer status is restored first, then explicitly suspended linked accounts are reactivated. A crash can therefore leave accounts blocked, not spuriously enabled under a suspended customer.

## Relationship closure

A customer can move from `SUSPENDED` to `CLOSED` only when every linked customer account is already `CLOSED`.

Account closure itself requires the account to be suspended, ledger integrity to verify, its available balance to be zero, and no `CLAIMED` or `PENDING` inbound payment to be bound to that account.

## Canonical checkpoint

The customer-registry file hash is part of the G-BANK sovereign checkpoint root alongside account registry, ledger, receipts, execution/velocity state and inbound state.

Tampering or omission therefore changes the canonical state root and fails checkpoint verification.

## Reality boundary

```text
G_BANK_CUSTOMER_REGISTRY = IMPLEMENTED
G_BANK_CUSTOMER_ONBOARDING_GATE = IMPLEMENTED
G_BANK_CUSTOMER_SUSPENSION_PROPAGATION = IMPLEMENTED
G_BANK_CUSTOMER_ACCOUNT_PROVISIONING = IMPLEMENTED
G_BANK_EXTERNAL_IBAN_ASSIGNMENT_VERIFICATION = IMPLEMENTED

RAW_KYC_PROVIDER = EXTERNAL / NOT_EMULATED
IBAN_ISSUER_AUTHORITY = NOT_CLAIMED
REGULATORY_CUSTOMER_DUE_DILIGENCE_APPROVAL = NOT_CLAIMED
LIVE_SETTLEMENT_RIGHTS = NOT_CLAIMED
```

No customer-control artifact performs an external payment or moves value by itself.
