# G-FINANCE-010 — Production readiness preflight

Status: IMPLEMENTED_ON_FEATURE_BRANCH

## Goal

Verify that the configured TrueLayer production identity can authenticate and submit a valid signed non-payment readiness request without enabling live payments.

## Hard safety boundary

The command requires:

- `TRUELAYER_ENV=live`
- `G_BANK_ENABLE_LIVE=false`
- `G_BANK_ENABLE_PROVIDER_PROBE=true`
- a probe authorization secret of at least 32 characters

It refuses to run if live execution is enabled.

## External provider checks

The preflight uses the existing bounded provider-readiness path against the TrueLayer production auth/API endpoints.

Success requires:

- production access token obtained
- signed non-payment readiness request accepted
- provider HTTP status 204

No payment endpoint is called.

## Receipt

Output:

`.secrets/evidence/g-finance-production-preflight.json`

Schema:

`g-finance-production-preflight/1.0`

The receipt binds:

- `rail=G_BANK`
- `evidence_type=AUTHENTICATION_READBACK`
- `provider=truelayer`
- `environment=PRODUCTION`
- `proof_scope=PRODUCTION_NON_PAYMENT_PREFLIGHT`
- `provider_authentication_verified=true`
- `access_token_obtained=true`
- `request_signature_accepted=true`
- `provider_http_status=204`
- `live_execution_enabled=false`
- `external_actions_enabled=false`
- `payment_endpoint_called=false`
- `payment_created=false`
- `bank_authorization_started=false`
- `value_moved=false`
- `verified_write=false`
- `verified_value_flow=false`
- `go_live_promotion_performed=false`
- canonical SHA-256

## Failure behavior

If TrueLayer production rejects token scope, credentials, signing, or the readiness request, the command exits blocked and writes no successful receipt.

A failure therefore cannot promote production authentication.

## Commands

```bash
npm run test:banking:g-finance-production-preflight
npm run proof:banking:g-finance-production-preflight -- --force
```

This phase does not create, authorize, execute, or settle any payment.
