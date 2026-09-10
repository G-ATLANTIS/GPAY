const test = require('node:test');
const assert = require('node:assert/strict');
const { SharedPaymentStateRuntime } = require('../backend/utils/payment-state-runtime');

class InMemoryCasAdapter {
  constructor() { this.records = new Map(); }
  key(p, id) { return `${p}:${id}`; }
  async reserve(record) {
    const k = this.key(record.provider, record.providerPaymentId);
    if (this.records.has(k)) return { created: false, record: { ...this.records.get(k) } };
    const row = {
      provider: record.provider,
      provider_payment_id: record.providerPaymentId,
      stage: 'RECEIVED',
      version: 0,
      processed_at: record.processedAt,
      data: record.data || {},
    };
    this.records.set(k, row);
    return { created: true, record: { ...row } };
  }
  async get(provider, providerPaymentId) {
    const row = this.records.get(this.key(provider, providerPaymentId));
    return row ? { ...row, data: { ...row.data } } : null;
  }
  async compareAndSetStage(provider, providerPaymentId, expectedVersion, nextStage, patch = {}) {
    await new Promise(resolve => setImmediate(resolve));
    const k = this.key(provider, providerPaymentId);
    const row = this.records.get(k);
    if (!row || row.version !== expectedVersion) {
      const err = new Error('Payment state compare-and-set conflict');
      err.code = 'PAYMENT_STATE_CAS_CONFLICT';
      throw err;
    }
    const next = {
      ...row,
      stage: nextStage,
      version: row.version + 1,
      data: { ...row.data, ...patch },
    };
    this.records.set(k, next);
    return { ...next, data: { ...next.data } };
  }
}

test('shared runtime reserves one canonical payment identity', async () => {
  const adapter = new InMemoryCasAdapter();
  const a = new SharedPaymentStateRuntime(adapter);
  const b = new SharedPaymentStateRuntime(adapter);
  const now = '2026-09-10T17:40:00.000Z';
  const [first, second] = await Promise.all([
    a.begin('mollie', 'tr_shared_1', now),
    b.begin('mollie', 'tr_shared_1', now),
  ]);
  assert.equal([first.created, second.created].filter(Boolean).length, 1);
  assert.equal(first.state.processedAt, now);
  assert.equal(second.state.processedAt, now);
});

test('two stale workers cannot both advance the same version', async () => {
  const adapter = new InMemoryCasAdapter();
  await adapter.reserve({ provider: 'mollie', providerPaymentId: 'tr_race', processedAt: '2026-09-10T17:40:00.000Z' });
  const snapshotA = await adapter.get('mollie', 'tr_race');
  const snapshotB = await adapter.get('mollie', 'tr_race');

  const results = await Promise.allSettled([
    adapter.compareAndSetStage('mollie', 'tr_race', snapshotA.version, 'PROVIDER_VERIFIED', { worker: 'A' }),
    adapter.compareAndSetStage('mollie', 'tr_race', snapshotB.version, 'PROVIDER_VERIFIED', { worker: 'B' }),
  ]);

  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(results.filter(r => r.status === 'rejected').length, 1);
  assert.equal(results.find(r => r.status === 'rejected').reason.code, 'PAYMENT_STATE_CAS_CONFLICT');

  const final = await adapter.get('mollie', 'tr_race');
  assert.equal(final.stage, 'PROVIDER_VERIFIED');
  assert.equal(final.version, 1);
});
