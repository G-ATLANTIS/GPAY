const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gpay-processing-state-'));
process.env.GPAY_STATE_DIR = tempDir;

const {
  beginPayment,
  getPaymentState,
  advancePayment,
} = require('../backend/utils/payment-processing-state');

test('payment state advances monotonically to committed', () => {
  const startedAt = '2026-09-10T17:00:00.000Z';
  const first = beginPayment('mollie', 'tr_state_1', startedAt);
  assert.equal(first.created, true);
  assert.equal(first.state.stage, 'RECEIVED');
  assert.equal(first.state.processedAt, startedAt);

  const verified = advancePayment('mollie', 'tr_state_1', 'PROVIDER_VERIFIED', {
    providerStatus: 'paid',
    orderId: 'ORDER-STATE-1',
    amount: '10.00',
    currency: 'EUR',
  }, '2026-09-10T17:00:01.000Z');
  assert.equal(verified.state.stage, 'PROVIDER_VERIFIED');
  assert.equal(verified.state.processedAt, startedAt);

  const prepared = advancePayment('mollie', 'tr_state_1', 'EFFECTS_PREPARED', {
    receiptHash: 'a'.repeat(64),
    settlementEventId: 'b'.repeat(64),
  }, '2026-09-10T17:00:02.000Z');
  assert.equal(prepared.state.stage, 'EFFECTS_PREPARED');
  assert.equal(prepared.state.processedAt, startedAt);

  const committed = advancePayment('mollie', 'tr_state_1', 'COMMITTED', {}, '2026-09-10T17:00:03.000Z');
  assert.equal(committed.state.stage, 'COMMITTED');
  assert.equal(committed.state.processedAt, startedAt);
});

test('restarting processing reuses the original processedAt timestamp', () => {
  const original = beginPayment('mollie', 'tr_state_restart', '2026-09-10T17:10:00.000Z');
  const retry = beginPayment('mollie', 'tr_state_restart', '2026-09-10T18:10:00.000Z');
  assert.equal(original.created, true);
  assert.equal(retry.created, false);
  assert.equal(retry.state.processedAt, '2026-09-10T17:10:00.000Z');
});

test('stage rollback is denied fail-closed', () => {
  beginPayment('mollie', 'tr_state_rollback', '2026-09-10T17:20:00.000Z');
  advancePayment('mollie', 'tr_state_rollback', 'EFFECTS_PREPARED');
  assert.throws(
    () => advancePayment('mollie', 'tr_state_rollback', 'PROVIDER_VERIFIED'),
    err => err && err.code === 'PAYMENT_STAGE_ROLLBACK_DENIED'
  );
});

test('same-stage replay is idempotent', () => {
  beginPayment('mollie', 'tr_state_replay', '2026-09-10T17:30:00.000Z');
  const first = advancePayment('mollie', 'tr_state_replay', 'PROVIDER_VERIFIED', { orderId: 'ORDER-A' });
  const second = advancePayment('mollie', 'tr_state_replay', 'PROVIDER_VERIFIED', { orderId: 'ORDER-B' });
  assert.equal(first.changed, true);
  assert.equal(second.changed, false);
  assert.equal(getPaymentState('mollie', 'tr_state_replay').orderId, 'ORDER-A');
});

test.after(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});
