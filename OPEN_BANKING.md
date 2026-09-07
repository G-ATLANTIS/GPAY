# G-Bank Open Banking — TrueLayer Payments v3

## Status

This integration is **fail-closed**.

- Default environment: `sandbox`
- Live execution is denied unless `TRUELAYER_ENV=live` **and** `G_BANK_ENABLE_LIVE=true`.
- Live payments also require the beneficiary IBAN to be allowlisted and a transaction-bound `X-G-Bank-Approval` HMAC.
- A payment is never considered complete merely because a payment object was created.
- The user must authorize the payment in the bank/TrueLayer hosted flow.
- For external-account payments, TrueLayer `executed` means the bank accepted the submitted payment. It is **not proof that the creditor account settled**.
- `VERIFIED_VALUE_FLOW` therefore stays inactive until independent settlement/receipt evidence is available.

## Required configuration

Use runtime secrets only. Never commit secrets.

```
TRUELAYER_ENV=sandbox
TRUELAYER_CLIENT_ID=
TRUELAYER_CLIENT_SECRET=
TRUELAYER_SIGNING_KID=
TRUELAYER_PRIVATE_KEY_B64=
TRUELAYER_RETURN_URI=http://localhost:5173/bank-return
G_BANK_MAX_PAYMENT_EUR=100
G_BANK_ENABLE_LIVE=false
G_BANK_APPROVAL_SECRET=
G_BANK_ALLOWED_BENEFICIARY_IBANS=
```

Generate a P-521 / secp521r1 signing keypair and upload only the public key to the provider. Keep the private key in a secure secret store/KMS if possible.

### Native request signing

The backend implements TrueLayer request-signing v2 with Node's built-in `crypto`: ES512 on a P-521 key, detached JWS, `tl_version=2`, and `Idempotency-Key` bound through `tl_headers`. Offline tests generate a fresh P-521 keypair and cryptographically verify the resulting signature. A live or sandbox TrueLayer `/test-signature` check is still required before promotion.

## Endpoints

- `GET /api/open-banking/health`
  - Reports environment, missing configuration, live gate and max amount.
- `POST /api/open-banking/create-payment`
  - Creates an EUR bank-transfer payment candidate.
  - Requires a beneficiary IBAN/name/reference and payer identity fields.
  - Uses an idempotency key and signed request.
  - Returns a hosted bank-authorization URL.
- `GET /api/open-banking/payment/:paymentId`
  - Reads current provider/bank execution status.
  - Does not claim creditor settlement from `executed` alone.

## Security blockers before live

1. Rotate/revoke any payment-provider credential that was ever committed to Git history.
2. Obtain TrueLayer production approval/credentials for the intended use case.
3. Generate a fresh signing keypair; upload public key; store private key outside Git.
4. Register the production return URI in provider settings.
5. Set a deliberately small `G_BANK_MAX_PAYMENT_EUR` for first live verification.
6. Configure `G_BANK_ALLOWED_BENEFICIARY_IBANS` with only pre-verified recipients.
7. Keep `G_BANK_APPROVAL_SECRET` outside Git. For each live payment compute HMAC-SHA256 over `Idempotency-Key|amount_in_minor|IBAN|reference` and send it as `X-G-Bank-Approval`.
8. Validate the native P-521 / ES512 detached-JWS implementation against TrueLayer's sandbox `/test-signature` endpoint.
9. Complete a sandbox payment through explicit user authorization.
10. Only then consider enabling `G_BANK_ENABLE_LIVE=true`.
11. For a real purchase, verify beneficiary, amount, contract/invoice and settlement receipt separately.

## Reality-bound graph states

```
CONFIGURED_SANDBOX
  -> PAYMENT_CREATED
  -> USER_BANK_AUTHORIZATION
  -> BANK_ACCEPTED_EXECUTION
  -> SETTLEMENT_EVIDENCE
  -> VERIFIED_VALUE_FLOW
```

No step may be skipped or inferred.
