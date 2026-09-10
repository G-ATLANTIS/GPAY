'use strict';

// TRUELAYER-SANDBOX-E2E-VERIFICATION-P0
//
// Two layers:
//   1. Always-on unit tests for the E2E harness's pure guards (no network,
//      no credentials) — these run in normal CI.
//   2. An OPT-IN external integration test, skipped unless
//      G_TRUELAYER_RUN_SANDBOX_E2E=true AND TRUELAYER_ENV=sandbox. It creates at
//      most one sandbox payment, reads it back, verifies idempotency +
//      reconciliation, and leaves an evidence receipt. Normal CI never depends
//      on provider credentials.

const test = require('node:test');
const assert = require('node:assert/strict');

const { runE2E, assertSandboxBoundary, preflightConfig, classifyBinding } = require('../../scripts/verify-truelayer-sandbox-e2e');

// -------------------------------------------------------------------------
// 1. Always-on guard unit tests
// -------------------------------------------------------------------------
test('assertSandboxBoundary: sandbox env passes', () => {
  const b = assertSandboxBoundary({ TRUELAYER_ENV: 'sandbox', G_BANK_ENABLE_LIVE: 'false' });
  assert.equal(b.ok, true);
  assert.equal(b.target_environment, 'SANDBOX');
  assert.match(b.auth_host, /truelayer-sandbox\.com$/);
  assert.match(b.api_host, /truelayer-sandbox\.com$/);
  assert.equal(b.production_payment_execution, 'DENY');
});

test('assertSandboxBoundary: TRUELAYER_ENV=live is rejected (no fallback)', () => {
  const b = assertSandboxBoundary({ TRUELAYER_ENV: 'live' });
  assert.equal(b.ok, false);
  assert.ok(b.reasons.some((r) => /PRODUCTION|sandbox/.test(r)));
});

test('assertSandboxBoundary: G_BANK_ENABLE_LIVE=true is rejected even with TRUELAYER_ENV=sandbox', () => {
  const b = assertSandboxBoundary({ TRUELAYER_ENV: 'sandbox', G_BANK_ENABLE_LIVE: 'true' });
  assert.equal(b.ok, false);
  assert.ok(b.reasons.some((r) => /G_BANK_ENABLE_LIVE=true/.test(r)));
});

test('assertSandboxBoundary: unset TRUELAYER_ENV is rejected', () => {
  assert.equal(assertSandboxBoundary({}).ok, false);
});

test('preflightConfig: emits only booleans / hashes, never raw secret values', () => {
  const env = {
    TRUELAYER_CLIENT_ID: 'super-secret-client-id-value',
    TRUELAYER_CLIENT_SECRET: 'super-secret-client-secret-value',
    TRUELAYER_SIGNING_KID: '11111111-2222-4333-8444-555555555555',
    TRUELAYER_PRIVATE_KEY_PEM: '-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n',
    TRUELAYER_RETURN_URI: 'https://g-bank.test/api/open-banking/return',
    TRUELAYER_ENV: 'sandbox',
    G_SPINE_AUTHORIZATION_SECRET: 'x'.repeat(48),
  };
  const cp = preflightConfig(env);
  const blob = JSON.stringify(cp);
  assert.equal(blob.includes('super-secret-client-id-value'), false);
  assert.equal(blob.includes('super-secret-client-secret-value'), false);
  assert.equal(blob.includes('BEGIN PRIVATE KEY'), false);
  assert.equal(cp.present.TRUELAYER_CLIENT_ID, true);
  assert.equal(cp.present.TRUELAYER_CLIENT_SECRET, true);
  assert.match(cp.client_id_sha256, /^[0-9a-f]{64}$/);
  assert.match(cp.signing_kid_sha256, /^[0-9a-f]{64}$/);
  assert.equal(cp.return_uri_shape_ok, true);
});

test('classifyBinding: STRONG / WEAK / MISMATCH', () => {
  const strong = { checks: { payment_id: true, environment: true, amount: true, currency: true, beneficiary_iban: true, beneficiary_reference: true, intent_sha256: true, destination_binding: true }, mismatch: [] };
  assert.equal(classifyBinding(strong), 'STRONG');
  assert.equal(classifyBinding({ checks: { payment_id: true, environment: true }, mismatch: [] }), 'WEAK');
  assert.equal(classifyBinding({ checks: { payment_id: true }, mismatch: ['amount'] }), 'MISMATCH');
  assert.equal(classifyBinding(null), 'WEAK');
});

test('runE2E aborts (no provider call) when the sandbox boundary is not satisfied', async () => {
  const ev = await runE2E({ env: { TRUELAYER_ENV: 'live', G_BANK_ENABLE_LIVE: 'false' }, noWrite: true });
  assert.equal(ev.status, 'BLOCKED');
  assert.match(ev.abort_reason, /SANDBOX BOUNDARY NOT SATISFIED/);
  assert.equal(ev.payment_create_verified, 'UNVERIFIED');
  assert.equal(ev.oauth_verified, 'UNVERIFIED');
  assert.equal(ev.secrets_redacted, true);
});

test('runE2E aborts when sandbox config is incomplete (no provider call)', async () => {
  const ev = await runE2E({
    env: { TRUELAYER_ENV: 'sandbox', G_BANK_ENABLE_LIVE: 'false', G_BANK_ENABLE_SANDBOX_EXTERNAL: 'true' },
    noWrite: true,
  });
  assert.equal(ev.status, 'BLOCKED');
  assert.match(ev.abort_reason, /config preflight incomplete/);
  assert.equal(ev.payment_create_verified, 'UNVERIFIED');
});

// -------------------------------------------------------------------------
// 2. Opt-in external sandbox E2E
// -------------------------------------------------------------------------
const E2E_ENABLED = process.env.G_TRUELAYER_RUN_SANDBOX_E2E === 'true';

test('external: TrueLayer sandbox E2E (discover -> create -> readback -> replay -> reconcile)', { skip: E2E_ENABLED ? false : 'set G_TRUELAYER_RUN_SANDBOX_E2E=true and TRUELAYER_ENV=sandbox to run' }, async () => {
  assert.equal(String(process.env.TRUELAYER_ENV || '').toLowerCase(), 'sandbox', 'refusing: TRUELAYER_ENV must be sandbox');
  assert.notEqual(process.env.G_BANK_ENABLE_LIVE, 'true', 'refusing: G_BANK_ENABLE_LIVE=true');

  const ev = await runE2E({ env: process.env });

  // The receipt must never contain secret material.
  const blob = JSON.stringify(ev);
  for (const k of ['TRUELAYER_CLIENT_SECRET', 'access_token', 'BEGIN PRIVATE KEY', 'Bearer ']) {
    assert.equal(blob.includes(k), false, `evidence leaked ${k}`);
  }
  assert.equal(ev.secrets_redacted, true);
  assert.ok(['VERIFIED_L4', 'VERIFIED_L3', 'PARTIAL', 'BLOCKED'].includes(ev.status));

  if (ev.status === 'VERIFIED_L4' || ev.status === 'VERIFIED_L3') {
    assert.equal(ev.canonical_execution_state, 'VERIFIED_SUCCESS');
    assert.equal(ev.payment_create_verified, 'TRUE');
    assert.match(ev.provider_payment_id_sha256, /^[0-9a-f]{64}$/);
    assert.equal(ev.idempotency_verified, 'TRUE');
    assert.equal(ev.audit_chain_verified, 'TRUE');
    assert.equal(ev.reconcile_result, 'EFFECT_CONFIRMED');
  }
  if (ev.status === 'VERIFIED_L4') {
    assert.equal(ev.binding_strength, 'STRONG');
    assert.equal(ev.assurance_level, 'L4');
    assert.equal(ev.readback_verified, 'TRUE');
  }
  console.log(`\nG_TRUELAYER_SANDBOX_E2E_STATUS = ${ev.status}`);
});
