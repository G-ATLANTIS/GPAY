# ATLAS Payment Intelligence Bridge v1

The bridge lets GPAY consume evidence-grounded rail advice from the G-System intelligence layer without giving that layer payment authority.

## Contract

Input attestation schema: `atlas-payment-rail-intelligence-attestation-v1`.

The bridge verifies:
- subject is `GPAY`;
- EUR amount matches the bound payment intent;
- optional intent binding hash matches;
- attestation freshness;
- attestation SHA-256 integrity;
- intelligence explicitly claims no execution authority, no provider call and no value movement;
- preferred rail exists in the GPAY core route set.

## Authority boundary

The bridge never changes GPAY core authorization. It returns `final_execution_authority=GPAY_CORE_ONLY`, `provider_call_permitted=false`, and `value_moved=false`.

A converged intelligence/core result means only that the advisory preference and GPAY's eligible adapter agree. Real execution still requires the existing GPAY owner approval, beneficiary, bank-limit, SCA, callback/readback, idempotency, entitlement and high-value gates.

## Status command

Set:

- `ATLAS_PAYMENT_INTENT_PATH`
- `ATLAS_PAYMENT_ROUTE_DECISION_PATH`
- `ATLAS_PAYMENT_INTELLIGENCE_ATTESTATION_PATH`

Then run:

```bash
node scripts/atlas-open-banking-intelligence-status.js
```

The command performs no network or payment action.
