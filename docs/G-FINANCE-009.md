# G-FINANCE-009 — TrueLayer provider authentication evidence

Status: IMPLEMENTED_ON_FEATURE_BRANCH

## Purpose

Produce a short-lived, hash-bound proof that the configured G-Bank TrueLayer identity can:

1. obtain a TrueLayer access token, and
2. submit a signed non-payment `POST /test-signature` request accepted with HTTP 204.

This proves provider authentication/signing only.

## Safety boundary

The proof is SANDBOX-only in this phase and refuses:

- non-sandbox TrueLayer environments,
- `G_BANK_ENABLE_LIVE=true`,
- disabled provider probes,
- weak/missing probe authorization secrets.

The readiness call creates no payment, starts no bank authorization, moves no value, and does not claim write or settlement verification.

## Receipt

Output:

`.secrets/evidence/g-finance-provider-auth.json`

Schema:

`g-finance-provider-auth/1.0`

Required facts include:

- `rail=G_BANK`
- `evidence_type=AUTHENTICATION_READBACK`
- `provider=truelayer`
- `environment=SANDBOX`
- `proof_scope=NON_PAYMENT_AUTHENTICATION`
- `probe_endpoint=/test-signature`
- `provider_authentication_verified=true`
- `access_token_obtained=true`
- `request_signature_accepted=true`
- `provider_http_status=204`
- `payment_created=false`
- `bank_authorization_started=false`
- `value_moved=false`
- `verified_write=false`
- `verified_value_flow=false`
- canonical SHA-256.

The receipt is mode 0600 and cannot be overwritten without explicit `--force`.

## Commands

```bash
npm run test:banking:g-finance-auth
npm run proof:banking:g-finance-auth
```
