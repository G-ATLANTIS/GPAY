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
TRUELAYER_RETURN_URI=http://localhost:4000/api/open-banking/return
G_BANK_MAX_PAYMENT_EUR=100
G_BANK_ENABLE_LIVE=false
G_BANK_ENABLE_PROVIDER_PROBE=false
G_BANK_PROVIDER_PROBE_SECRET=
G_BANK_OPERATOR_SECRET=
G_BANK_APPROVAL_SECRET=
G_BANK_ALLOWED_BENEFICIARY_IBANS=
G_BANK_SECRET_ROTATION_RECEIPT_FILE=.secrets/evidence/secret-rotation.json
G_BANK_SANDBOX_VERIFICATION_RECEIPT_FILE=.secrets/evidence/sandbox-verification.json
```

Generate a P-521 / secp521r1 signing keypair and upload only the public key to the provider. Keep the private key in a secure secret store/KMS if possible.

A local bootstrap command is included:

```bash
npm run keygen:banking
```

It writes the private/public keypair under `.secrets/truelayer/`, refuses to overwrite an existing keypair unless explicitly forced, and `.secrets/` is Git-ignored. Upload only the generated public key to TrueLayer Console.

### Native request signing

The backend implements TrueLayer request-signing v2 with Node's built-in `crypto`: ES512 on a P-521 key, detached JWS, `tl_version=2`, and `Idempotency-Key` bound through `tl_headers`. Offline tests generate a fresh P-521 keypair and cryptographically verify the resulting signature. A live or sandbox TrueLayer `/test-signature` check is still required before promotion.

## Endpoints

- `GET /api/open-banking/health`
  - Reports environment, missing configuration, live gate and max amount.
- `GET /api/open-banking/graph-status`
  - Returns a non-secret G_REAL_EXECUTION_GRAPH view of provider-auth, payment-write and value-flow edges.
  - Local configuration never activates a verified edge by itself.
- `GET /api/open-banking/return`
  - Public HPP return endpoint; no operator secret is required because a user browser is redirected here.
  - Accepts only a locally known `payment_id`.
  - Never performs a provider call and never treats the return as payment success.
  - `error=tl_hpp_abandoned` is reported only as user abandonment, not as a settlement result.
- `POST /api/open-banking/provider-readiness`
  - Requires `G_BANK_ENABLE_PROVIDER_PROBE=true`.
  - Requires a matching `X-G-Bank-Probe-Authorization` header backed by a separate `G_BANK_PROVIDER_PROBE_SECRET`.
  - Obtains a Payments access token and submits a signed nonce to TrueLayer `/test-signature`.
  - Expects HTTP 204 for a successful provider-authentication/signature check.
  - Creates no payment, starts no bank authorization, and moves no value.
- `POST /api/open-banking/create-payment`
  - Creates an EUR bank-transfer payment candidate.
  - Requires a beneficiary IBAN/name/reference and payer identity fields.
  - Uses an idempotency key and signed request.
  - Returns a hosted bank-authorization URL.
- `GET /api/open-banking/payment/:paymentId`
  - Reads current provider/bank execution status using a backend bearer token.
  - Does not send modification-only Idempotency-Key/Tl-Signature headers.
  - Does not claim creditor settlement from `executed` alone.

## Security blockers before live

1. Rotate/revoke any payment-provider credential that was ever committed to Git history.
2. Obtain TrueLayer production approval/credentials for the intended use case.
3. Generate a fresh signing keypair; upload public key; store private key outside Git.
4. Register the production return URI in provider settings.
5. Set a deliberately small `G_BANK_MAX_PAYMENT_EUR` for first live verification.
6. Configure `G_BANK_ALLOWED_BENEFICIARY_IBANS` with only pre-verified recipients.
7. Keep `G_BANK_APPROVAL_SECRET` outside Git. For each live payment compute HMAC-SHA256 over `Idempotency-Key|amount_in_minor|IBAN|reference` and send it as `X-G-Bank-Approval`.
8. Set `G_BANK_ENABLE_PROVIDER_PROBE=true` temporarily and call `POST /api/open-banking/provider-readiness`; require `request_signature_accepted=true` and provider HTTP 204.
9. Set `G_BANK_ENABLE_PROVIDER_PROBE=false` again after the readiness check.
10. Complete a sandbox payment through explicit user authorization.
11. Only then consider enabling `G_BANK_ENABLE_LIVE=true`.
12. For a real purchase, verify beneficiary, amount, contract/invoice and settlement receipt separately.

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


## Operator commands

Local provider/configuration readiness check:

```bash
npm run check:banking:env
```

This command validates required TrueLayer variables, parses the signing key, requires P-521, checks the return URI and reports whether the live/probe gates are open. It prints no secret values and performs no network request.

Generate a transaction-bound live approval only after separately verifying the beneficiary, amount and payment reference:

```bash
npm run approve:banking -- \
  --confirm-approval \
  --idempotency-key <uuid> \
  --amount-eur <amount> \
  --iban <allowlisted-iban> \
  --reference <reference>
```

The generator is offline, requires an explicit confirmation flag, enforces the configured beneficiary allowlist and payment ceiling, and writes the HMAC token to `.secrets/approvals/` instead of printing it. The token is bound to the exact idempotency key, amount-in-minor, IBAN and reference. Generating a token does not contact a bank or create a payment.


## Evidence receipts are release gates

Live mode now requires two non-secret receipt references:

- `G_BANK_SECRET_ROTATION_RECEIPT`: reference to external/provider-side evidence that the historically exposed payment credential was revoked or rotated.
- `G_BANK_SANDBOX_VERIFICATION_RECEIPT`: reference to evidence that sandbox provider authentication/signing and the intended authorization path were verified.

These environment values are **references**, not proof by themselves. The underlying evidence must be independently reviewable. Their purpose is to prevent the runtime from being switched to live while the required evidence has not even been recorded.


## Recording release evidence

Record provider-side secret rotation evidence:

```bash
npm run evidence:banking -- \
  --confirm-evidence \
  --type SECRET_ROTATION \
  --provider mollie \
  --evidence-ref <provider-ticket-or-console-reference> \
  --artifact <optional-local-evidence-file>
```

Record sandbox provider verification evidence:

```bash
npm run evidence:banking -- \
  --confirm-evidence \
  --type SANDBOX_VERIFICATION \
  --provider truelayer \
  --evidence-ref <sandbox-test-reference> \
  --artifact <saved-provider-readiness-json>
```

The sandbox record requires an artifact so its SHA-256 is bound into the receipt. Both records contain their own integrity hash. Runtime validation checks record integrity and timestamp freshness; sandbox verification expires after 30 days, while secret-rotation evidence is accepted for up to 10 years.

Set live runtime paths to:

```
G_BANK_SECRET_ROTATION_RECEIPT_FILE=.secrets/evidence/secret-rotation.json
G_BANK_SANDBOX_VERIFICATION_RECEIPT_FILE=.secrets/evidence/sandbox-verification.json
```

A valid local record is still not treated as independent external proof; it is an audit-bound reference to evidence that must remain reviewable.


## Verified payment webhooks

Configure the TrueLayer Console webhook URI so its path exactly matches:

```
TRUELAYER_WEBHOOK_PATH=/api/open-banking/webhook
G_BANK_WEBHOOK_RECEIPT_DIR=.secrets/runtime/webhook-events
G_BANK_PAYMENT_INTENT_DIR=.secrets/runtime/payment-intents
```

The backend preserves the exact raw JSON bytes for this route before parsing. Incoming webhooks are accepted only after:

1. `Tl-Signature` parses as a detached v2 JWS.
2. `alg=ES512` and `tl_version=2`.
3. `jku` exactly equals the expected TrueLayer well-known JWKS URL for the selected environment.
4. The JWK selected by `kid` is a P-521 EC public key.
5. `X-TL-Webhook-Timestamp` is included in `tl_headers`, present in the request and within the supported retry/freshness window.
6. The signature verifies against the exact HTTP method, configured path, signed headers and raw request body.
7. The JSON contains an event ID and event version.

The JWKS fetch forbids redirects. This prevents an attacker-controlled JKU from becoming an SSRF/open-redirect path.

TrueLayer may deliver the same webhook more than once. Duplicate `event_id` values are recorded in an atomically-created receipt file under `G_BANK_WEBHOOK_RECEIPT_DIR/<environment>/`. The receipt binds event ID, event type/version, payment ID, webhook timestamp, raw-body SHA-256, TrueLayer signing `kid`/`jku`, environment and an integrity hash.

A second delivery with the same event ID and same raw body is acknowledged as a duplicate. The same event ID with a different raw-body hash is rejected as an event-ID/body conflict. Receipt files are written mode 0600 and fsynced before the handler acknowledges the event.

This survives application/process restarts only when `G_BANK_WEBHOOK_RECEIPT_DIR` is backed by storage that itself survives those restarts. The runtime cannot infer whether a container filesystem is persistent. Live configuration therefore requires the receipt directory to be explicitly set, and `npm run check:banking:env` performs a local atomic write/fsync/delete readiness probe. Infrastructure-level persistence still requires independent deployment evidence.

A verified webhook remains an observation only:

```
WEBHOOK_SIGNATURE_VERIFIED
  -> PROVIDER_EVENT_OBSERVED
  -> PAYMENT_STATUS_EVIDENCE_CANDIDATE
  -> NO AUTOMATIC PAYMENT WRITE
  -> NO AUTOMATIC VERIFIED_VALUE_FLOW
```

Even `payment_executed` does not prove that an external creditor received funds. Independent settlement/receipt evidence remains required for the G_REAL_EXECUTION_GRAPH value-flow edge.


### Webhook receipt storage

For sandbox, the default local location is:

```
G_BANK_WEBHOOK_RECEIPT_DIR=.secrets/runtime/webhook-events
```

For live use, set this explicitly to a protected persistent volume/disk location. Do not place it in Git or a public/shared directory. The runtime separates receipts into `sandbox/` and `live/` subdirectories.

Operational invariants:

- first valid event: atomic create + file fsync;
- exact duplicate: 2xx acknowledgement, no second side effect;
- same event ID with different raw body: fail closed;
- tampered stored receipt: fail closed;
- receipt includes TrueLayer signing key provenance;
- receipt persistence across machine/container replacement is **not verified** until the deployment storage itself is independently verified.


### JWKS caching and key rotation

Webhook verification uses only the exact TrueLayer well-known JWKS URL for the selected environment.

The verifier caches JWKS for at most 10 minutes and only reuses a cached set when it already contains the signature `kid`. If a new `kid` appears, the verifier refreshes JWKS before verification. Stale cache is never used as a fallback after a failed refresh.

Network hardening for JWKS retrieval:

- redirects: disabled;
- maximum response size: 64 KiB;
- maximum accepted key count: 50;
- optional response content type, when present, must be JSON;
- keys must be EC/P-521 when those JWK fields are supplied;
- fetched JWKS must contain the requested `kid`.

This follows the same JKU+KID cache principle shown in TrueLayer's official webhook-server example while adding bounded TTL and response limits.


## Operator API authorization

All Open Banking HTTP routes except the TrueLayer webhook require:

```
X-G-Bank-Operator-Authorization: <G_BANK_OPERATOR_SECRET>
```

`G_BANK_OPERATOR_SECRET` must contain at least 32 characters and must remain outside Git.

Protected routes include:

- health/status;
- execution-graph status;
- provider readiness;
- payment creation;
- payment status reads;
- future non-webhook routes mounted on the Open Banking router.

The webhook is intentionally exempt from this operator header because TrueLayer cannot know a G-Bank private secret. Its trust boundary is instead the verified `Tl-Signature`, exact JKU allowlist, JWKS key, timestamp and raw-body signature binding.

The operator secret does not authorize a live payment by itself. Live payment creation still separately requires the transaction-bound `X-G-Bank-Approval`, beneficiary allowlist, amount ceiling and all live release evidence.


## Durable payment-intent receipts

Before the first network submission of a payment, GPAY atomically creates an immutable intent receipt under:

```
G_BANK_PAYMENT_INTENT_DIR=<persistent protected location>
```

The receipt binds:

- idempotency key;
- EUR amount in minor units;
- SHA-256 of the exact provider request body;
- SHA-256 of beneficiary IBAN;
- SHA-256 of the payment reference;
- environment and creation timestamp.

It deliberately does **not** persist the raw IBAN, payer email/details, payment reference, or the hosted-page resource token.

After TrueLayer confirms payment-object creation, GPAY creates separate immutable creation and payment-ID binding receipts. This yields fail-closed retry semantics:

```
NEW IDEMPOTENCY KEY
  -> INTENT RECEIPT
  -> PROVIDER SUBMISSION
  -> CREATION RECEIPT
  -> PAYMENT-ID BINDING
```

If the intent receipt exists but no creation receipt exists, the prior submission is treated as ambiguous and automatic create retry is denied. Operator/provider review is required before any retry.

If the same idempotency key is presented with different amount/body/beneficiary/reference hashes, the request is rejected as an idempotency conflict.

If a creation receipt already exists, GPAY returns a conflict pointing to the existing payment ID and requires the status-read path instead of creating again.

For live mode, `G_BANK_PAYMENT_INTENT_DIR` must be explicitly set. `npm run check:banking:env` performs an atomic write/fsync/delete probe, but infrastructure-level persistence across machine/container replacement still requires independent verification.


### Hosted page return is not payment success

TrueLayer appends the payment ID to the configured `return_uri` after the hosted-page flow. A cancelled flow can additionally include `error=tl_hpp_abandoned`.

GPAY treats that redirect only as a browser-navigation signal:

```
HPP RETURN
  -> VERIFY LOCAL PAYMENT-ID BINDING
  -> AUTHORIZATION FLOW RETURNED
  -> WAIT FOR VERIFIED WEBHOOK / AUTHENTICATED STATUS READ
  -> NO SUCCESS CLAIM
  -> NO VERIFIED_VALUE_FLOW
```

A random or unknown payment ID is rejected. Even a locally known payment ID never becomes successful from the return URL alone.


## HTTP surface isolation

The Open Banking router is mounted before the application's general CORS middleware. Operator/payment APIs are therefore not exposed through the application's broad browser CORS policy.

The G-Bank surface also applies:

- JSON request body limit: 64 KiB;
- `Cache-Control: no-store`;
- `Pragma: no-cache`;
- `X-Content-Type-Options: nosniff`;
- `Referrer-Policy: no-referrer`;
- `Cross-Origin-Resource-Policy: same-origin`;
- explicit G-Bank 404 handling so unknown banking paths do not fall through into the general application middleware.

This does not replace operator authentication. Non-webhook/non-return routes still require `X-G-Bank-Operator-Authorization`.


### Return URI runtime policy

Payment creation is fail-closed unless `TRUELAYER_RETURN_URI` satisfies the runtime policy:

- path must be exactly `/api/open-banking/return`;
- no username/password component;
- no query string;
- no fragment;
- live environment requires HTTPS;
- sandbox allows HTTPS, or HTTP only for localhost/loopback.

The configured webhook path must likewise be exactly:

```
/api/open-banking/webhook
```

This prevents a successful code deployment from silently using a less-protected redirect or a webhook path that the runtime route cannot actually verify.
