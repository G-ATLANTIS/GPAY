# G-Bank / payment mutation-path inventory

G-BANK-CANONICAL-LIVE-ROUTING-P0, Phase 1. Every code path capable of causing
an external banking/payment effect, and its status after this task.

Search terms used: `createPayment`, `payments.create`, `execute(`, `https.request`,
`axios`, `fetch(`, `MollieLiveAdapter`, `GBankLiveCore`, `TRUELAYER`, `POST /payments`,
`allowExternalEffects`, `G_BANK_ENABLE_LIVE`, `mollieClient`.

## A. Mollie — in scope, routed through the spine

| # | file | symbol | provider / op | authorization (before) | authorization (after) | idempotency (before) | idempotency (after) | bypassed spine before? | after |
|---|------|--------|---------------|------------------------|-----------------------|----------------------|---------------------|------------------------|-------|
| 1 | `backend/g-bank-live-v1/live-core.js` | `GBankLiveCore.execute()` | Mollie create+readback | own HMAC approval (`approval.js`) | **retired** — constructor throws | own file store | n/a (retired) | **yes** | removed |
| 2 | `scripts/g-bank-live-v1.js` | `execute --execute-live` | Mollie create | operator confirm env + old approval | operator confirm env + **spine `createAuthorization`** bound to canonical request hash; runs `executeVerified()` | old store via GBankLiveCore | **spine `IdempotencyStore` + `SequenceStore`** | **yes** | routed |
| 3 | `backend/routes/mollie.js` | `POST /api/mollie/create-payment` | `mollieClient.payments.create` (@mollie/api-client) | **none** (only `checkFraud`) | operator-secret header (timing-safe) → server mints spine authorization → `executeVerified()` | **none** | spine stores | **yes (worst: zero controls)** | routed; fail-closed by default |
| 4 | `backend/g-bank-live-v1/providers/mollie-live.js` | `MollieLiveAdapter.createPayment()` | Mollie `POST /v2/payments` (raw `https.request`) | caller's responsibility | reachable only from `MollieSpineConnector`; guarded by CI bypass rule + `assertConfigured()` (`live_` key) | Idempotency-Key header only | unchanged (spine adds the durable canonical record) | was directly importable | import-restricted (allowlist) |
| — | `backend/g-verified-execution-spine/connectors/mollie-spine-connector.js` | `MollieSpineConnector.execute()/readback()` | shim over #4 | via `executeVerified()` only | via `executeVerified()` only | spine | spine | n/a (new) | canonical |

## B. Other external providers — out of Mollie scope; DENY-by-default

| # | file | symbol | provider / op | status after this task |
|---|------|--------|---------------|------------------------|
| 5 | `backend/routes/openbanking.js` | `POST /api/open-banking/create-payment` → `axios.post(${apiBase}/v3/payments)` | TrueLayer live bank transfer | **DENY by default.** Handler now returns 403 unless `G_BANK_ALLOW_UNSPINED_TRUELAYER=I_ACCEPT_UNSPINED_EXECUTION`. Legacy stack (own approval `assertLiveApproval` + own receipts). **Not yet spine-routed — #1 remaining bypass**, tracked for a follow-up TrueLayer spine connector. |
| 6 | `backend/routes/pulsepay.js` | `POST /api/pulsepay/create-payment` → `axios.post(api.pulsepay.io/v1/payments)` | PulsePay | **DENY by default.** Returns 403 unless `G_BANK_ALLOW_UNSPINED_PULSEPAY=I_ACCEPT_UNSPINED_EXECUTION`. Demo scaffolding (`'YOUR_API_KEY'` default); no spine connector exists. |
| 7 | `backend/routes/webhook.js` | `POST /mollie/webhook` → `mollieClient.payments.get` then token-reward / invoice / email | Mollie webhook side effects | **Neutralised** to a 501 fail-closed stub. Was dead code (mounted by no server) that granted rewards + emailed on an unverified webhook body. |

## C. Sandbox / diagnostic only — refuse `G_BANK_ENABLE_LIVE=true`

| file | symbol | note |
|------|--------|------|
| `scripts/run-banking-sandbox-smoke.js` | `createPayment()` | throws if `G_BANK_ENABLE_LIVE=true`; sandbox smoke only |
| `scripts/probe-banking-production-provider.js` | `axios.post` | forces `G_BANK_ENABLE_LIVE=false`; read-only auth probe |
| `scripts/banking-go-live.js` | `fetch(baseUrl/)` | local readiness health check, not a provider mutation |
| `scripts/generate-banking-sandbox-webhook.js`, `route-banking-sandbox-webhooks.js`, `test-official-truelayer-*.js`, `run-g-finance-*-proof.js` | various | all refuse `G_BANK_ENABLE_LIVE=true`; sandbox/diagnostic |
| `scripts/g-payment-*.js` (chat-intent → rail-router → execution-gate → …entitlement-gate → live-oauth-proof) | evidence-file producers | produce canonical JSON gate records; none call a provider mutation endpoint (live-oauth-proof does an OAuth *token* read only, `payment_endpoint_called:false`). Not execution paths. |

## D. TrueLayer read/OAuth (non-mutating) — allowed to use `axios`

`getAccessToken` (`/connect/token`), `performProviderReadiness`, `fetchPaymentStatus`
(`GET /v3/payments/:id`), webhook JWKS fetch. Read-only; not flagged by the bypass
guard (it targets `.payments.create` / adapter imports, not reads).

## Enforcement now in place

* `scripts/ci/check-spine-bypass.js` (`npm run guard:spine-bypass`) fails CI if
  non-allowlisted `backend/**` or `scripts/**` code imports `MollieLiveAdapter`,
  imports a spine connector directly, calls `*.payments.create/cancel` /
  `*.refunds.create`, imports `@mollie/api-client`, or does `new GBankLiveCore(`.
* Allowlist (13 files) = spine internals, connector impls, the adapter itself,
  the sanctioned CLI + route, and isolation tests.
* `GBankLiveCore` constructor throws.
* Rows 5–7 are DENY unless an explicit, logged env acknowledgement is set.
