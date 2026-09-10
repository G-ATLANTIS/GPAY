const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

function freshLedger(tempDir) {
  process.env.GPAY_STATE_DIR = tempDir;
  delete require.cache[require.resolve('../backend/utils/payment-effect-ledger')];
  return require('../backend/utils/payment-effect-ledger');
}

test('effect ids are stable and effect type is validated', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gpay-effects-'));
  const { effectId } = freshLedger(dir);
  assert.equal(effectId('mollie', 'tr_1', 'invoice'), 'mollie:tr_1:invoice');
  assert.throws(() => effectId('mollie', 'tr_1', 'unknown'), { code: 'PAYMENT_EFFECT_TYPE_INVALID' });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('local ledger prepares once and reuses completed result', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gpay-effects-'));
  const { LocalPaymentEffectLedger } = freshLedger(dir);
  const ledger = new LocalPaymentEffectLedger();
  const first = await ledger.prepare('mollie', 'tr_2', 'invoice', { orderId: 'o1' });
  assert.equal(first.created, true);
  assert.equal(first.record.status, 'PREPARED');
  const completed = await ledger.complete('mollie', 'tr_2', 'invoice', { invoicePath: '/tmp/invoice.pdf' });
  assert.equal(completed.changed, true);
  assert.equal(completed.record.status, 'COMPLETED');
  const replay = await ledger.prepare('mollie', 'tr_2', 'invoice', { orderId: 'different' });
  assert.equal(replay.created, false);
  assert.equal(replay.record.data.invoicePath, '/tmp/invoice.pdf');
  const completeReplay = await ledger.complete('mollie', 'tr_2', 'invoice', { invoicePath: '/tmp/other.pdf' });
  assert.equal(completeReplay.changed, false);
  assert.equal(completeReplay.record.data.invoicePath, '/tmp/invoice.pdf');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('completion without preparation fails closed', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gpay-effects-'));
  const { LocalPaymentEffectLedger } = freshLedger(dir);
  const ledger = new LocalPaymentEffectLedger();
  await assert.rejects(
    () => ledger.complete('mollie', 'tr_3', 'email', { sentAt: new Date().toISOString() }),
    { code: 'PAYMENT_EFFECT_NOT_PREPARED' }
  );
  fs.rmSync(dir, { recursive: true, force: true });
});
