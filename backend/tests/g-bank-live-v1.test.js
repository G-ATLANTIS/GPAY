'use strict';

// After G-BANK-CANONICAL-LIVE-ROUTING-P0 the g-bank-live-v1 module keeps only
// primitives (canonical hashing, approval HMAC, idempotency store, receipt
// ledger, Mollie adapter). GBankLiveCore — the old second execution authority —
// is retired. Live routing is covered by
// backend/tests/g-bank-canonical-live-routing.test.js.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { normalizeIntent } = require('../g-bank-live-v1/canonical');
const { createApproval, verifyApproval } = require('../g-bank-live-v1/approval');
const { GBankLiveCore, requireLiveExecution, RETIREMENT_MESSAGE } = require('../g-bank-live-v1/live-core');

test('requireLiveExecution stays fail-closed on the three env guards', () => {
  assert.throws(() => requireLiveExecution({}), /g_bank_live_execution_disabled/);
  assert.throws(() => requireLiveExecution({ G_BANK_ENABLE_LIVE: 'true' }), /g_bank_external_actions_disabled/);
  assert.throws(
    () =>
      requireLiveExecution({
        G_BANK_ENABLE_LIVE: 'true',
        G_BANK_EXTERNAL_ACTIONS_ENABLED: 'true',
        G_BANK_SIMULATED_LIVE_SUCCESS: 'true',
      }),
    /simulated_live_success_forbidden/,
  );
  assert.equal(
    requireLiveExecution({ G_BANK_ENABLE_LIVE: 'true', G_BANK_EXTERNAL_ACTIONS_ENABLED: 'true' }),
    true,
  );
});

test('GBankLiveCore is retired and cannot be constructed / used as an execution authority', () => {
  assert.equal(GBankLiveCore.retired, true);
  assert.throws(() => new GBankLiveCore({ adapters: {} }), new RegExp('retired'));
  assert.match(RETIREMENT_MESSAGE, /executeVerified/);
});

test('regression: canonical intent + approval HMAC primitives unchanged', () => {
  const i = normalizeIntent({
    intent_id: `intent-${crypto.randomUUID()}`,
    amount_minor: 1234,
    currency: 'EUR',
    description: 'primitive regression',
    destination_binding: 'merchant:test-profile',
    redirect_url: 'https://example.test/return',
    webhook_url: 'https://example.test/webhook',
    metadata: { test: true },
  });
  const env = { G_BANK_APPROVAL_SECRET: 'x'.repeat(64) };
  const key = crypto.randomUUID();
  const token = createApproval({ intent: i, provider: 'p', idempotencyKey: key }, env);
  assert.equal(
    verifyApproval(token, { intent: i, provider: 'p', idempotencyKey: key }, env).intent_sha256,
    i.intent_sha256,
  );
  assert.throws(
    () => verifyApproval(token, { intent: i, provider: 'p', idempotencyKey: crypto.randomUUID() }, env),
    /approval_idempotency_mismatch/,
  );
});
