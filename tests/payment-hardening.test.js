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
const { GCOIN, createGcoinSettlementIntent } = require('../backend/utils/gcoin-settlement-intent');

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
    settlementEventId: 'settlement-event-1',
    settlementMode: 'intent_only',
    settlementExecutionStatus: 'not_attempted',
    settlementContractAddress: GCOIN.contractAddress,
    settlementChainId: GCOIN.chainId,
    tokens: 150,
  };
  const a = createReceipt(input);
  const b = createReceipt(input);
  assert.equal(a.receiptHash, b.receiptHash);
  assert.equal(typeof canonicalReceiptPayload(input), 'string');
});

test('processed payment record is created once and then reused', () => {
  const receipt = createReceipt({
    provider: 'mollie', providerPaymentId: 'tr_test_once', orderId: 'ORDER-ONCE',
    amount: '1.00', currency: 'EUR', status: 'paid',
    processedAt: '2026-09-10T14:00:00.000Z', rewardEventId: 'reward-once', tokens: 10,
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

test('GCOIN settlement intent is deterministic and bound to canonical contract', () => {
  const input = {
    provider: 'mollie', providerPaymentId: 'tr_gcoin_1', orderId: 'ORDER-GCOIN-1',
    amount: '15.00', currency: 'EUR', rewardEventId: 'reward-gcoin-1', gcoinAmount: '150',
  };
  const a = createGcoinSettlementIntent(input);
  const b = createGcoinSettlementIntent(input);
  assert.equal(a.settlementEventId, b.settlementEventId);
  assert.equal(a.contractAddress, '0xF2923D79903Aa13a62d408b4fabF748dB87B8c30');
  assert.equal(a.chainId, 1);
  assert.equal(a.mode, 'intent_only');
  assert.equal(a.executionStatus, 'not_attempted');
  assert.equal(a.broadcast, false);
  assert.equal(a.signerUsed, false);
  assert.equal(a.transactionHash, null);
});

test('different payments produce different GCOIN settlement IDs', () => {
  const base = {
    provider: 'mollie', orderId: 'ORDER-GCOIN', amount: '1.00', currency: 'EUR',
    rewardEventId: 'reward-gcoin', gcoinAmount: '10',
  };
  const a = createGcoinSettlementIntent({ ...base, providerPaymentId: 'tr_A' });
  const b = createGcoinSettlementIntent({ ...base, providerPaymentId: 'tr_B' });
  assert.notEqual(a.settlementEventId, b.settlementEventId);
});

test('GCOIN settlement intent denies every broadcast request', () => {
  assert.throws(() => createGcoinSettlementIntent({
    provider: 'mollie', providerPaymentId: 'tr_denied', orderId: 'ORDER-DENIED',
    amount: '1.00', currency: 'EUR', rewardEventId: 'reward-denied', gcoinAmount: '10',
    broadcast: true,
  }), err => err && err.code === 'GCOIN_BROADCAST_DENIED');
});

test('GCOIN settlement intent fails closed on missing required identity fields', () => {
  assert.throws(() => createGcoinSettlementIntent({
    provider: 'mollie', providerPaymentId: '', orderId: 'ORDER-MISSING',
    amount: '1.00', currency: 'EUR', rewardEventId: 'reward-missing', gcoinAmount: '10',
  }), /providerPaymentId is required/);
});

test.after(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});
