const {
  beginPayment,
  getPaymentState,
  advancePayment,
} = require('./payment-processing-state');
const { loadConfiguredPaymentStateAdapter } = require('./payment-state-adapter');

class LocalPaymentStateRuntime {
  async ensureReady() {}

  async begin(provider, providerPaymentId, now = new Date().toISOString()) {
    const result = beginPayment(provider, providerPaymentId, now);
    return { created: result.created, state: result.state };
  }

  async get(provider, providerPaymentId) {
    return getPaymentState(provider, providerPaymentId);
  }

  async advance(provider, providerPaymentId, nextStage, patch = {}) {
    const result = advancePayment(provider, providerPaymentId, nextStage, patch);
    return { changed: result.changed, state: result.state };
  }
}

class SharedPaymentStateRuntime {
  constructor(adapter) {
    this.adapter = adapter;
  }

  async ensureReady() {
    if (typeof this.adapter.ensureSchema === 'function') await this.adapter.ensureSchema();
  }

  async begin(provider, providerPaymentId, now = new Date().toISOString()) {
    const result = await this.adapter.reserve({
      provider,
      providerPaymentId,
      processedAt: now,
      data: { processingStartedAt: now },
    });
    return { created: result.created, state: normalizeSharedRecord(result.record) };
  }

  async get(provider, providerPaymentId) {
    const record = await this.adapter.get(provider, providerPaymentId);
    return record ? normalizeSharedRecord(record) : null;
  }

  async advance(provider, providerPaymentId, nextStage, patch = {}) {
    const current = await this.adapter.get(provider, providerPaymentId);
    if (!current) {
      const err = new Error('Payment processing state does not exist');
      err.code = 'PAYMENT_STATE_MISSING';
      throw err;
    }
    if (current.stage === nextStage) return { changed: false, state: normalizeSharedRecord(current) };
    const next = await this.adapter.compareAndSetStage(
      provider,
      providerPaymentId,
      Number(current.version),
      nextStage,
      patch
    );
    return { changed: true, state: normalizeSharedRecord(next) };
  }
}

function normalizeSharedRecord(record) {
  const data = record.data || {};
  const processedAt = record.processed_at instanceof Date
    ? record.processed_at.toISOString()
    : record.processed_at || record.processedAt;
  return {
    ...data,
    provider: record.provider,
    providerPaymentId: record.provider_payment_id || record.providerPaymentId,
    stage: record.stage,
    version: Number(record.version || 0),
    processedAt,
    processingStartedAt: data.processingStartedAt || processedAt,
  };
}

function createPaymentStateRuntime(env = process.env) {
  const adapter = loadConfiguredPaymentStateAdapter(env);
  return adapter ? new SharedPaymentStateRuntime(adapter) : new LocalPaymentStateRuntime();
}

module.exports = {
  LocalPaymentStateRuntime,
  SharedPaymentStateRuntime,
  normalizeSharedRecord,
  createPaymentStateRuntime,
};
