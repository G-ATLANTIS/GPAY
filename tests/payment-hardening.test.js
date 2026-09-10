const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gpay-hardening-'));
process.env.GPAY_STATE_DIR = tempDir;

const { createReceipt, canonicalReceiptPayload } = require('../backend/utils/payment-receipt');
const { getProcessed, recordProcessed } = require('../backend/utils/payment-idempotency-store');
const { acquirePaymentLock } = require('../backend/utils/payment-lock');

test('receipt hash is deterministic for the same canonical transaction', () => {
  const input = {
    provider: 'mollie',
    providerPaymentId: 'tr_test_123',
    orderId: 'ORDER-123',
    amount: '15.00',
    currency: 'EUR',
    status: 'paid',
    processedAt: '2026-09-10T14:00:00.000Z',
    rewardEventId: 'reward-event-1',
    tokens: 150,
  };
  const a = createReceipt(input);
  const b = createReceipt(input);
  assert.equal(a.receiptHash, b.receiptHash);
  assert.equal(typeof canonicalReceiptPayload(input), 'string');
});

test('processed payment record is created once and then reused', () => {
  const receipt = createReceipt({
    provider: 'mollie',
    providerPaymentId: 'tr_test_once',
    orderId: 'ORDER-ONCE',
    amount: '1.00',
    currency: 'EUR',
    status: 'paid',
    processedAt: '2026-09-10T14:00:00.000Z',
    rewardEventId: 'reward-once',
    tokens: 10,
  });

  const first = recordProcessed('mollie', 'tr_test_once', receipt);
  const second = recordProcessed('mollie', 'tr_test_once', receipt);
  assert.equal(first.created, true);
  assert.equal(second.created, false);
  assert.equal(getProcessed('mollie', 'tr_test_once').receiptHash, receipt.receiptHash);
});

test('per-payment lock rejects concurrent local acquisition', () => {
  const first = acquirePaymentLock('mollie', 'tr_lock_test');
  assert.equal(first.acquired, true);

  const second = acquirePaymentLock('mollie', 'tr_lock_test');
  assert.equal(second.acquired, false);

  first.release();
  const third = acquirePaymentLock('mollie', 'tr_lock_test');
  assert.equal(third.acquired, true);
  third.release();
});

test.after(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});
