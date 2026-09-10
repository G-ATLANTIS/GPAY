const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

function loadStore(tempDir) {
  process.env.GPAY_STATE_DIR = tempDir;
  delete require.cache[require.resolve('../backend/utils/payment-intent-store')];
  return require('../backend/utils/payment-intent-store');
}

test('payment intent binds one immutable provider payment and verifies canonical fields', () => {
  const original = process.env.GPAY_STATE_DIR;
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gpay-intent-'));
  try {
    const { createPaymentIntent, bindProviderPayment, verifyPaymentIntent } = loadStore(tempDir);
    const intent = createPaymentIntent({
      orderId: 'order-123',
      amount: '12.30',
      currency: 'EUR',
      email: 'Buyer@Example.com',
    });
    assert.match(intent.intentId, /^gpi_/);
    assert.equal(intent.providerPaymentId, null);
    assert.equal(intent.status, 'CREATED');
    assert.equal(intent.emailHash.length, 64);

    const bound = bindProviderPayment(intent.intentId, 'tr_test_123');
    assert.equal(bound.providerPaymentId, 'tr_test_123');
    assert.equal(bound.status, 'PROVIDER_BOUND');

    const verified = verifyPaymentIntent({
      intentId: intent.intentId,
      providerPaymentId: 'tr_test_123',
      orderId: 'order-123',
      amount: '12.30',
      currency: 'EUR',
      email: 'buyer@example.com',
    });
    assert.equal(verified.ok, true);

    assert.throws(
      () => bindProviderPayment(intent.intentId, 'tr_other'),
      error => error.code === 'PAYMENT_INTENT_REBIND_DENIED'
    );
  } finally {
    if (original === undefined) delete process.env.GPAY_STATE_DIR;
    else process.env.GPAY_STATE_DIR = original;
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('payment intent verification rejects forged or mismatched payment data', () => {
  const original = process.env.GPAY_STATE_DIR;
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gpay-intent-'));
  try {
    const { createPaymentIntent, bindProviderPayment, verifyPaymentIntent } = loadStore(tempDir);
    const intent = createPaymentIntent({
      orderId: 'order-9', amount: '5.00', currency: 'EUR', email: 'a@example.com',
    });
    bindProviderPayment(intent.intentId, 'tr_valid');

    assert.equal(verifyPaymentIntent({
      intentId: 'gpi_missing', providerPaymentId: 'tr_valid', orderId: 'order-9', amount: '5.00', currency: 'EUR', email: 'a@example.com',
    }).reason, 'intent_not_found');

    assert.equal(verifyPaymentIntent({
      intentId: intent.intentId, providerPaymentId: 'tr_forged', orderId: 'order-9', amount: '5.00', currency: 'EUR', email: 'a@example.com',
    }).reason, 'provider_payment_mismatch');

    assert.equal(verifyPaymentIntent({
      intentId: intent.intentId, providerPaymentId: 'tr_valid', orderId: 'order-9', amount: '6.00', currency: 'EUR', email: 'a@example.com',
    }).reason, 'amount_mismatch');

    assert.equal(verifyPaymentIntent({
      intentId: intent.intentId, providerPaymentId: 'tr_valid', orderId: 'order-9', amount: '5.00', currency: 'USD', email: 'a@example.com',
    }).reason, 'currency_mismatch');

    assert.equal(verifyPaymentIntent({
      intentId: intent.intentId, providerPaymentId: 'tr_valid', orderId: 'other-order', amount: '5.00', currency: 'EUR', email: 'a@example.com',
    }).reason, 'order_mismatch');

    assert.equal(verifyPaymentIntent({
      intentId: intent.intentId, providerPaymentId: 'tr_valid', orderId: 'order-9', amount: '5.00', currency: 'EUR', email: 'other@example.com',
    }).reason, 'email_mismatch');
  } finally {
    if (original === undefined) delete process.env.GPAY_STATE_DIR;
    else process.env.GPAY_STATE_DIR = original;
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
