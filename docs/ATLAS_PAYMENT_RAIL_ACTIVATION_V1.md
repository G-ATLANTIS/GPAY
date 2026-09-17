# ATLAS Payment Rail Activation v1

Goal: promote the first of six canonical GPAY rails to `VERIFIED_READ_ONLY` before any payment-write capability is considered.

Canonical rails: bunq native draft, Adyen outbound, Tink Open Banking, Yapily Connect, ATLAS own PISP, and ATLAS direct SEPA.

Activation is evidence-driven and fail-closed. A positive read-only probe requires a fresh provider-bound proof SHA-256, immutable source reference, observation time, and expiry. Environment booleans alone cannot create verified readiness.

The first activation target is bunq because GPAY already has a host-executable read-only bootstrap client and bunq supports API-key based production sessions. The read-only bootstrap may create installation/device/session context, but financial writes remain forbidden. Draft-payment execution is a later, separate gate.

Adyen, Tink and Yapily remain candidates but require their own production onboarding/credentials. ATLAS own PISP requires DNB authorisation, eIDAS identity and bank registration. Direct SEPA requires licensed PSP status, EPC scheme adherence, settlement/network access, HSM/signing controls and VOP readiness.

Invariants:
- `payment_write_enabled=false` throughout activation v1.
- `provider_call_permitted=false` for payment endpoints.
- `value_moved=false`.
- Read-only network probes require explicit operator opt-in.
- Missing/stale/unbound evidence fails closed.
