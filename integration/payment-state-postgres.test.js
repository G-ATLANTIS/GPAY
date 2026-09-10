const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { Pool } = require('pg');
const { PostgresPaymentStateAdapter } = require('../backend/utils/payment-state-postgres');

const connectionString = process.env.GPAY_POSTGRES_URL;

if (!connectionString) {
  test('postgres integration requires GPAY_POSTGRES_URL', { skip: true }, () => {});
} else {
  test('real postgres CAS allows exactly one stale worker to advance a payment version', async () => {
    const pool = new Pool({ connectionString, max: 4 });
    const adapter = new PostgresPaymentStateAdapter(pool);
    const provider = 'mollie';
    const paymentId = `tr_ci_${crypto.randomUUID().replace(/-/g, '')}`;
    const processedAt = new Date().toISOString();

    try {
      await adapter.ensureSchema();
      const reserved = await adapter.reserve({
        provider,
        providerPaymentId: paymentId,
        processedAt,
        data: { testRun: true },
      });
      assert.equal(reserved.created, true);
      assert.equal(Number(reserved.record.version), 0);
      assert.equal(reserved.record.stage, 'RECEIVED');

      const workerA = await adapter.get(provider, paymentId);
      const workerB = await adapter.get(provider, paymentId);
      assert.equal(Number(workerA.version), 0);
      assert.equal(Number(workerB.version), 0);

      const results = await Promise.allSettled([
        adapter.compareAndSetStage(provider, paymentId, Number(workerA.version), 'PROVIDER_VERIFIED', { worker: 'A' }),
        adapter.compareAndSetStage(provider, paymentId, Number(workerB.version), 'PROVIDER_VERIFIED', { worker: 'B' }),
      ]);

      const fulfilled = results.filter(result => result.status === 'fulfilled');
      const rejected = results.filter(result => result.status === 'rejected');
      assert.equal(fulfilled.length, 1);
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].reason?.code, 'PAYMENT_STATE_CAS_CONFLICT');

      const finalState = await adapter.get(provider, paymentId);
      assert.equal(finalState.stage, 'PROVIDER_VERIFIED');
      assert.equal(Number(finalState.version), 1);
      assert.ok(['A', 'B'].includes(finalState.data.worker));
    } finally {
      await pool.query(
        'DELETE FROM gpay_payment_state WHERE provider=$1 AND provider_payment_id=$2',
        [provider, paymentId]
      ).catch(() => {});
      await pool.end();
    }
  });
}
