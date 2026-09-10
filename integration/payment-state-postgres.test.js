const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { Pool } = require('pg');
const { PostgresPaymentStateAdapter } = require('../backend/utils/payment-state-postgres');
const { PostgresPaymentIntentAdapter } = require('../backend/utils/payment-intent-postgres');
const { SharedPaymentIntentRuntime } = require('../backend/utils/payment-intent-runtime');
const { normalizeEmailHash } = require('../backend/utils/payment-intent-store');
const { PostgresPaymentEffectLedger } = require('../backend/utils/payment-effect-ledger');
const { prepareVerifiedPaymentTransaction } = require('../backend/utils/payment-postgres-transaction');

const connectionString = process.env.GPAY_POSTGRES_URL;

async function createBoundIntent(pool, { intentId, paymentId, orderId, amount, email }) {
  const adapter = new PostgresPaymentIntentAdapter(pool);
  await adapter.ensureSchema();
  await adapter.create({
    intentId,
    provider: 'mollie',
    orderId,
    amount,
    currency: 'EUR',
    emailHash: normalizeEmailHash(email),
  });
  await adapter.bindProviderPayment(intentId, paymentId);
}

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

  test('real postgres stores and verifies immutable GPAY payment intent provenance', async () => {
    const pool = new Pool({ connectionString, max: 4 });
    const adapter = new PostgresPaymentIntentAdapter(pool);
    const runtime = new SharedPaymentIntentRuntime(adapter);
    const intentId = `gpi_${crypto.randomUUID()}`;
    const paymentId = `tr_ci_${crypto.randomUUID().replace(/-/g, '')}`;
    const email = 'ci-intent@example.invalid';

    try {
      await runtime.ensureReady();
      const created = await adapter.create({
        intentId,
        provider: 'mollie',
        orderId: 'ci-order-1',
        amount: '1.00',
        currency: 'EUR',
        emailHash: normalizeEmailHash(email),
      });
      assert.equal(created.intentId, intentId);
      assert.equal(created.providerPaymentId, null);
      assert.equal(created.status, 'CREATED');

      const bound = await runtime.bind(intentId, paymentId);
      assert.equal(bound.providerPaymentId, paymentId);
      assert.equal(bound.status, 'PROVIDER_BOUND');
      assert.equal(bound.version, 1);

      const verified = await runtime.verify({
        intentId,
        providerPaymentId: paymentId,
        orderId: 'ci-order-1',
        amount: '1.00',
        currency: 'EUR',
        email,
      });
      assert.equal(verified.ok, true);

      const wrongAmount = await runtime.verify({
        intentId,
        providerPaymentId: paymentId,
        orderId: 'ci-order-1',
        amount: '2.00',
        currency: 'EUR',
        email,
      });
      assert.equal(wrongAmount.ok, false);
      assert.equal(wrongAmount.reason, 'amount_mismatch');

      await assert.rejects(
        () => runtime.bind(intentId, `${paymentId}_other`),
        (error) => error?.code === 'PAYMENT_INTENT_REBIND_DENIED'
      );
    } finally {
      await pool.query('DELETE FROM gpay_payment_intent WHERE intent_id=$1', [intentId]).catch(() => {});
      await pool.end();
    }
  });

  test('real postgres payment effect ledger suppresses duplicate completion', async () => {
    const pool = new Pool({ connectionString, max: 4 });
    const ledger = new PostgresPaymentEffectLedger(pool);
    const paymentId = `tr_fx_${crypto.randomUUID().replace(/-/g, '')}`;

    try {
      await ledger.ensureReady();
      const prepared = await ledger.prepare('mollie', paymentId, 'invoice', { orderId: 'ci-order-fx' });
      assert.equal(prepared.created, true);
      assert.equal(prepared.record.status, 'PREPARED');

      const completed = await ledger.complete('mollie', paymentId, 'invoice', { invoicePath: '/tmp/ci.pdf' });
      assert.equal(completed.changed, true);
      assert.equal(completed.record.status, 'COMPLETED');
      assert.equal(completed.record.data.invoicePath, '/tmp/ci.pdf');

      const replay = await ledger.prepare('mollie', paymentId, 'invoice', { orderId: 'different' });
      assert.equal(replay.created, false);
      assert.equal(replay.record.status, 'COMPLETED');
      assert.equal(replay.record.data.invoicePath, '/tmp/ci.pdf');

      const completionReplay = await ledger.complete('mollie', paymentId, 'invoice', { invoicePath: '/tmp/other.pdf' });
      assert.equal(completionReplay.changed, false);
      assert.equal(completionReplay.record.data.invoicePath, '/tmp/ci.pdf');
    } finally {
      await pool.query('DELETE FROM gpay_payment_effect WHERE provider=$1 AND provider_payment_id=$2', ['mollie', paymentId]).catch(() => {});
      await pool.end();
    }
  });

  test('atomic postgres preparation commits state advancement and effect reservations together', async () => {
    const pool = new Pool({ connectionString, max: 4 });
    const state = new PostgresPaymentStateAdapter(pool);
    const effects = new PostgresPaymentEffectLedger(pool);
    const intentId = `gpi_tx_${crypto.randomUUID()}`;
    const paymentId = `tr_tx_${crypto.randomUUID().replace(/-/g, '')}`;
    const orderId = 'ci-order-tx-commit';
    const email = 'ci-tx-commit@example.invalid';

    try {
      await Promise.all([state.ensureSchema(), effects.ensureReady()]);
      await createBoundIntent(pool, { intentId, paymentId, orderId, amount: '3.25', email });

      const result = await prepareVerifiedPaymentTransaction({
        pool,
        provider: 'mollie',
        providerPaymentId: paymentId,
        intentId,
        orderId,
        amount: '3.25',
        currency: 'EUR',
        email,
        effectData: { reward: { event: 'r' }, invoice: { event: 'i' }, 'gcoin-intent': { event: 'g' } },
      });

      assert.equal(result.intentVerified, true);
      assert.equal(result.effectsReserved, true);
      assert.equal(result.state.stage, 'PROVIDER_VERIFIED');

      const savedState = await state.get('mollie', paymentId);
      assert.equal(savedState.stage, 'PROVIDER_VERIFIED');
      assert.equal(Number(savedState.version), 1);

      for (const effectType of ['reward', 'invoice', 'gcoin-intent']) {
        const effect = await effects.get('mollie', paymentId, effectType);
        assert.equal(effect.status, 'PREPARED');
      }
    } finally {
      await pool.query('DELETE FROM gpay_payment_effect WHERE provider=$1 AND provider_payment_id=$2', ['mollie', paymentId]).catch(() => {});
      await pool.query('DELETE FROM gpay_payment_state WHERE provider=$1 AND provider_payment_id=$2', ['mollie', paymentId]).catch(() => {});
      await pool.query('DELETE FROM gpay_payment_intent WHERE intent_id=$1', [intentId]).catch(() => {});
      await pool.end();
    }
  });

  test('atomic postgres preparation rolls back state and effects on failure', async () => {
    const pool = new Pool({ connectionString, max: 4 });
    const state = new PostgresPaymentStateAdapter(pool);
    const effects = new PostgresPaymentEffectLedger(pool);
    const intentId = `gpi_tx_${crypto.randomUUID()}`;
    const paymentId = `tr_tx_${crypto.randomUUID().replace(/-/g, '')}`;
    const orderId = 'ci-order-tx-rollback';
    const email = 'ci-tx-rollback@example.invalid';

    try {
      await Promise.all([state.ensureSchema(), effects.ensureReady()]);
      await createBoundIntent(pool, { intentId, paymentId, orderId, amount: '4.50', email });

      await assert.rejects(
        () => prepareVerifiedPaymentTransaction({
          pool,
          provider: 'mollie',
          providerPaymentId: paymentId,
          intentId,
          orderId,
          amount: '4.50',
          currency: 'EUR',
          email,
          injectFailureAfterEffects: true,
        }),
        (error) => error?.code === 'PAYMENT_TX_INJECTED_FAILURE'
      );

      const savedState = await state.get('mollie', paymentId);
      assert.equal(savedState, null);

      for (const effectType of ['reward', 'invoice', 'gcoin-intent']) {
        const effect = await effects.get('mollie', paymentId, effectType);
        assert.equal(effect, null);
      }

      const { rows } = await pool.query('SELECT provider_payment_id FROM gpay_payment_intent WHERE intent_id=$1', [intentId]);
      assert.equal(rows[0].provider_payment_id, paymentId);
    } finally {
      await pool.query('DELETE FROM gpay_payment_effect WHERE provider=$1 AND provider_payment_id=$2', ['mollie', paymentId]).catch(() => {});
      await pool.query('DELETE FROM gpay_payment_state WHERE provider=$1 AND provider_payment_id=$2', ['mollie', paymentId]).catch(() => {});
      await pool.query('DELETE FROM gpay_payment_intent WHERE intent_id=$1', [intentId]).catch(() => {});
      await pool.end();
    }
  });
}
