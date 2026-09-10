const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const path = require('path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { Pool } = require('pg');
const { PostgresPaymentEffectLedger } = require('../backend/utils/payment-effect-ledger');

const execFileAsync = promisify(execFile);
const connectionString = process.env.GPAY_POSTGRES_URL;
const workerPath = path.join(__dirname, 'helpers', 'payment-effect-worker.js');

async function runWorker(operation, paymentId, effectType, payload = {}) {
  const { stdout } = await execFileAsync(
    process.execPath,
    [workerPath, operation, 'mollie', paymentId, effectType, JSON.stringify(payload)],
    { env: { ...process.env, GPAY_POSTGRES_URL: connectionString } }
  );
  return JSON.parse(stdout.trim());
}

if (!connectionString) {
  test('multi-process postgres integration requires GPAY_POSTGRES_URL', { skip: true }, () => {});
} else {
  test('separate processes create only one canonical effect preparation and restart observes completion', async () => {
    const pool = new Pool({ connectionString, max: 2 });
    const ledger = new PostgresPaymentEffectLedger(pool);
    const paymentId = `tr_mp_${crypto.randomUUID().replace(/-/g, '')}`;

    try {
      await ledger.ensureReady();

      const [workerA, workerB] = await Promise.all([
        runWorker('prepare', paymentId, 'invoice', { worker: 'A', orderId: 'mp-order' }),
        runWorker('prepare', paymentId, 'invoice', { worker: 'B', orderId: 'mp-order' }),
      ]);

      const createdCount = [workerA, workerB].filter(result => result.created === true).length;
      assert.equal(createdCount, 1);

      const stored = await ledger.get('mollie', paymentId, 'invoice');
      assert.equal(stored.status, 'PREPARED');
      assert.ok(['A', 'B'].includes(stored.data.worker));

      const completion = await runWorker('complete', paymentId, 'invoice', { invoicePath: '/tmp/mp-invoice.pdf' });
      assert.equal(completion.changed, true);
      assert.equal(completion.record.status, 'COMPLETED');

      const restartedWorker = await runWorker('prepare', paymentId, 'invoice', { worker: 'restart' });
      assert.equal(restartedWorker.created, false);
      assert.equal(restartedWorker.record.status, 'COMPLETED');
      assert.equal(restartedWorker.record.data.invoicePath, '/tmp/mp-invoice.pdf');

      const rows = await pool.query(
        `SELECT COUNT(*)::int AS count
         FROM gpay_payment_effect
         WHERE provider=$1 AND provider_payment_id=$2 AND effect_type='invoice'`,
        ['mollie', paymentId]
      );
      assert.equal(rows.rows[0].count, 1);
    } finally {
      await pool.query('DELETE FROM gpay_payment_effect WHERE provider=$1 AND provider_payment_id=$2', ['mollie', paymentId]).catch(() => {});
      await pool.end();
    }
  });
}
