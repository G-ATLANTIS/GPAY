'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { normalizeIntent } = require('../g-bank-live-v1/canonical');
const { createApproval, verifyApproval } = require('../g-bank-live-v1/approval');
const { GBankLiveCore, requireLiveExecution } = require('../g-bank-live-v1/live-core');

function intent() {
  return normalizeIntent({
    intent_id: `intent-${crypto.randomUUID()}`,
    amount_minor: 1234,
    currency: 'EUR',
    description: 'G-Bank live core test',
    destination_binding: 'merchant:test-profile',
    redirect_url: 'https://example.test/return',
    webhook_url: 'https://example.test/webhook',
    metadata: { test: true },
  });
}

class FakeLiveAdapter {
  constructor() { this.name = 'fake-live'; this.createCount = 0; this.readCount = 0; }
  async preflight() {
    return { provider: this.name, environment: 'LIVE', authenticated: true, provider_http_status: 200 };
  }
  async createPayment({ intent }) {
    this.createCount += 1;
    return { provider: this.name, provider_http_status: 201, payment_id: 'tr_FAKE123', status: 'open', checkout_url: 'https://example.test/pay' };
  }
  async getPayment(paymentId) {
    this.readCount += 1;
    return { provider: this.name, provider_http_status: 200, payment_id: paymentId, status: 'open', mode: 'live', metadata: {} };
  }
}

async function run() {
  assert.throws(() => requireLiveExecution({}), /g_bank_live_execution_disabled/);
  assert.throws(() => requireLiveExecution({ G_BANK_ENABLE_LIVE: 'true' }), /g_bank_external_actions_disabled/);
  assert.throws(() => requireLiveExecution({
    G_BANK_ENABLE_LIVE: 'true',
    G_BANK_EXTERNAL_ACTIONS_ENABLED: 'true',
    G_BANK_SIMULATED_LIVE_SUCCESS: 'true',
  }), /simulated_live_success_forbidden/);

  const approvalEnv = { G_BANK_APPROVAL_SECRET: 'x'.repeat(64) };
  const i = intent();
  const key = crypto.randomUUID();
  const token = createApproval({ intent: i, provider: 'fake-live', idempotencyKey: key }, approvalEnv);
  assert.equal(verifyApproval(token, { intent: i, provider: 'fake-live', idempotencyKey: key }, approvalEnv).intent_sha256, i.intent_sha256);
  assert.throws(
    () => verifyApproval(token, { intent: i, provider: 'fake-live', idempotencyKey: crypto.randomUUID() }, approvalEnv),
    /approval_idempotency_mismatch/,
  );

  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-live-v1-'));
  const adapter = new FakeLiveAdapter();
  const env = {
    G_BANK_ENABLE_LIVE: 'true',
    G_BANK_EXTERNAL_ACTIONS_ENABLED: 'true',
    G_BANK_SIMULATED_LIVE_SUCCESS: 'false',
    G_BANK_APPROVAL_SECRET: approvalEnv.G_BANK_APPROVAL_SECRET,
  };
  const core = new GBankLiveCore({ adapters: { 'fake-live': adapter }, stateDir, env });
  const result = await core.execute({ rawIntent: i, provider: 'fake-live', approvalToken: token, idempotencyKey: key });
  assert.equal(result.verified_write, true);
  assert.equal(result.value_moved, false);
  assert.equal(adapter.createCount, 1);
  assert.equal(adapter.readCount, 1);

  const replay = await core.execute({ rawIntent: i, provider: 'fake-live', approvalToken: token, idempotencyKey: key });
  assert.equal(replay.payment_id, result.payment_id);
  assert.equal(adapter.createCount, 1, 'idempotent replay must not create another payment');
  assert.equal(adapter.readCount, 1, 'completed replay must not touch provider again');

  assert.equal(core.ledger.verify().valid, true);
  console.log('G-Bank LIVE v1 core tests: PASS');
}

run().catch(err => {
  console.error(err);
  process.exit(1);
});
