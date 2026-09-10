const test = require('node:test');
const assert = require('node:assert/strict');

const {
  assertForwardTransition,
  loadConfiguredPaymentStateAdapter,
} = require('../backend/utils/payment-state-adapter');
const {
  SCHEMA_SQL,
  PostgresPaymentStateAdapter,
} = require('../backend/utils/payment-state-postgres');

test('payment stage transitions are monotonic', () => {
  assert.equal(assertForwardTransition('RECEIVED', 'PROVIDER_VERIFIED'), true);
  assert.equal(assertForwardTransition('EFFECTS_PREPARED', 'COMMITTED'), true);
  assert.throws(
    () => assertForwardTransition('COMMITTED', 'PROVIDER_VERIFIED'),
    err => err && err.code === 'PAYMENT_STAGE_ROLLBACK_DENIED'
  );
});

test('unknown payment state backend fails closed', () => {
  assert.throws(
    () => loadConfiguredPaymentStateAdapter({ GPAY_PAYMENT_STATE_BACKEND: 'magic' }),
    err => err && err.code === 'PAYMENT_STATE_BACKEND_UNSUPPORTED'
  );
});

test('postgres backend fails closed without connection URL', () => {
  assert.throws(
    () => loadConfiguredPaymentStateAdapter({ GPAY_PAYMENT_STATE_BACKEND: 'postgres' }),
    err => err && err.code === 'PAYMENT_STATE_CONFIG_MISSING'
  );
});

test('postgres schema enforces unique provider payment identity and valid stages', () => {
  assert.match(SCHEMA_SQL, /PRIMARY KEY \(provider, provider_payment_id\)/);
  assert.match(SCHEMA_SQL, /CHECK \(stage IN \('RECEIVED','PROVIDER_VERIFIED','EFFECTS_PREPARED','COMMITTED'\)\)/);
});

test('postgres adapter issues version-bound CAS updates', async () => {
  const queries = [];
  const pool = {
    async query(sql, params = []) {
      queries.push({ sql, params });
      if (/^SELECT/.test(sql.trim())) {
        return { rows: [{ provider: 'mollie', provider_payment_id: 'tr_1', stage: 'PROVIDER_VERIFIED', version: 3, processed_at: new Date(), data: {} }] };
      }
      if (/^UPDATE/.test(sql.trim())) {
        return { rows: [{ provider: 'mollie', provider_payment_id: 'tr_1', stage: 'EFFECTS_PREPARED', version: 4, processed_at: new Date(), data: { receiptHash: 'abc' } }] };
      }
      return { rows: [] };
    },
  };

  const adapter = new PostgresPaymentStateAdapter(pool);
  const result = await adapter.compareAndSetStage('mollie', 'tr_1', 3, 'EFFECTS_PREPARED', { receiptHash: 'abc' });
  assert.equal(result.version, 4);
  const update = queries.find(q => /^UPDATE/.test(q.sql.trim()));
  assert.ok(update);
  assert.match(update.sql, /version=\$3/);
  assert.deepEqual(update.params.slice(0, 4), ['mollie', 'tr_1', 3, 'EFFECTS_PREPARED']);
});

test('postgres adapter surfaces CAS conflicts', async () => {
  const pool = {
    async query(sql) {
      if (/^SELECT/.test(sql.trim())) {
        return { rows: [{ provider: 'mollie', provider_payment_id: 'tr_2', stage: 'RECEIVED', version: 1, processed_at: new Date(), data: {} }] };
      }
      return { rows: [] };
    },
  };
  const adapter = new PostgresPaymentStateAdapter(pool);
  await assert.rejects(
    adapter.compareAndSetStage('mollie', 'tr_2', 1, 'PROVIDER_VERIFIED'),
    err => err && err.code === 'PAYMENT_STATE_CAS_CONFLICT'
  );
});
