# G-BANK LIVE Core v1

Status: additive production-control-plane candidate. Default posture is fail closed.

## Purpose

G-BANK LIVE Core is a provider-independent payment orchestration layer. It does not pretend to be a bank or bypass provider/PSP authorization. Real external effects occur only through an explicitly registered, authorized provider adapter.

Initial adapter: `mollie-live`.

Planned adapters: TrueLayer LIVE after the `payments` entitlement is verified; bank/SEPA adapters only where a real authorized interface exists.

## Non-negotiable invariants

- `G_BANK_ENABLE_LIVE=true` is required for a live side effect.
- `G_BANK_EXTERNAL_ACTIONS_ENABLED=true` is independently required.
- `G_BANK_SIMULATED_LIVE_SUCCESS=true` is rejected.
- Every live execution requires an HMAC-authenticated short-lived approval.
- Approval binds provider, canonical intent hash, exact amount, currency, destination-binding hash, and exact idempotency-key hash.
- The idempotency key is explicit and persisted before the provider POST.
- Completed identical replays return the recorded result without another provider POST.
- Ambiguous network outcomes are `UNKNOWN_REQUIRES_RECONCILIATION`; they never fail over automatically.
- Provider writes require provider readback before `verified_write=true`.
- `verified_value_flow=true` is only asserted from a provider readback state that proves value movement.
- Receipts form a local SHA-256 hash chain and are fsynced.
- Secrets and access tokens are never written into receipts.
- Mollie metadata stores only the hash of `destination_binding`, not its raw value.
- Mollie webhook state must not be trusted blindly; reconcile by fetching the payment from Mollie.

## Files

- `backend/g-bank-live-v1/canonical.js` — canonical intent + hashing.
- `backend/g-bank-live-v1/approval.js` — short-lived execution capability.
- `backend/g-bank-live-v1/idempotency-store.js` — atomic local execution ownership/results.
- `backend/g-bank-live-v1/receipt-ledger.js` — hash-chain evidence ledger.
- `backend/g-bank-live-v1/live-core.js` — fail-closed orchestration.
- `backend/g-bank-live-v1/providers/mollie-live.js` — Mollie LIVE adapter.
- `scripts/g-bank-live-v1.js` — guarded operator CLI.
- `backend/tests/g-bank-live-v1.test.js` — no-network core tests.

## Core test

```bash
node backend/tests/g-bank-live-v1.test.js
```

This test uses a fake provider. It does not make a network request and cannot move value.

## Mollie read-only production preflight

Load `MOLLIE_API_KEY` into the process environment without printing it, then:

```bash
node scripts/g-bank-live-v1.js preflight mollie-live
```

This performs only `GET /v2/methods?sequenceType=oneoff` and records read-only evidence.

## Prepare a payment intent

Example `intent.json`:

```json
{
  "intent_id": "intent-REPLACE-WITH-UNIQUE-ID",
  "amount_minor": 100,
  "currency": "EUR",
  "description": "Controlled live checkout",
  "destination_binding": "mollie-profile:EXPECTED-PROFILE",
  "redirect_url": "https://your-domain.example/payment/return",
  "webhook_url": "https://your-domain.example/api/payments/mollie/webhook",
  "metadata": {
    "order_id": "ORDER-123"
  }
}
```

Prepare an immutable execution bundle:

```bash
node scripts/g-bank-live-v1.js prepare intent.json .secrets/g-bank-live/bundle.json
```

No provider write occurs.

## Authorize the exact bundle

Provide a separate strong secret through `G_BANK_APPROVAL_SECRET` (minimum 32 bytes), then:

```bash
node scripts/g-bank-live-v1.js authorize \
  .secrets/g-bank-live/bundle.json \
  .secrets/g-bank-live/approval.json
```

The approval expires after five minutes by default. It is cryptographically bound to the exact provider, intent and idempotency key.

## Execute a real Mollie payment creation

Only after reviewing the bundle and approval:

```bash
export G_BANK_ENABLE_LIVE=true
export G_BANK_EXTERNAL_ACTIONS_ENABLED=true
export G_BANK_SIMULATED_LIVE_SUCCESS=false
export G_BANK_OPERATOR_CONFIRMATION=I_AUTHORIZE_THIS_REAL_PAYMENT

node scripts/g-bank-live-v1.js execute \
  .secrets/g-bank-live/bundle.json \
  .secrets/g-bank-live/approval.json \
  --execute-live
```

This can create a real Mollie LIVE payment/checkout. It must not be used as a substitute for a bank/PISP transfer to an arbitrary third-party beneficiary.

## Reconciliation

```bash
node scripts/g-bank-live-v1.js reconcile tr_REPLACE_WITH_PAYMENT_ID
```

For webhook processing, take only the payment identifier from the notification and perform provider readback before changing canonical G-BANK state.

## Provider routing policy

A provider may be selected automatically only before any side-effect attempt. Once a provider POST may have reached a provider, failover to a different rail is forbidden until reconciliation proves the first rail did not create/execute the payment.

TrueLayer and Mollie have different provider-side idempotency semantics, so G-BANK maintains its own longer-lived canonical idempotency record in addition to each provider's mechanism.

## Production promotion gates

Promotion should remain blocked until all of these are evidenced in the target runtime:

1. Local core tests pass.
2. Receipt-ledger verification passes.
3. Live provider read-only preflight succeeds.
4. Live credentials were rotated after any suspected exposure.
5. HTTPS redirect/webhook endpoints are deployed and controlled.
6. Operator approval secret is stored outside source control.
7. One deliberately small controlled live write is created and read back.
8. Webhook/readback reconciliation is demonstrated.
9. Retry and ambiguous-timeout drills prove no cross-provider duplicate execution.
10. Only then is the adapter eligible for normal live routing.
