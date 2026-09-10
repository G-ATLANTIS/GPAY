const crypto = require('crypto');
const {
  createPaymentIntent,
  bindProviderPayment,
  getPaymentIntent,
  verifyPaymentIntent,
  normalizeAmount,
  normalizeEmailHash,
} = require('./payment-intent-store');
const { PostgresPaymentIntentAdapter } = require('./payment-intent-postgres');

class LocalPaymentIntentRuntime {
  async ensureReady() {}
  async create(input) { return createPaymentIntent(input); }
  async bind(intentId, providerPaymentId) { return bindProviderPayment(intentId, providerPaymentId); }
  async get(intentId) { return getPaymentIntent(intentId); }
  async verify(input) { return verifyPaymentIntent(input); }
}

class SharedPaymentIntentRuntime {
  constructor(adapter) {
    this.adapter = adapter;
  }

  async ensureReady() {
    await this.adapter.ensureSchema();
  }

  async create({ orderId, amount, currency = 'EUR', email }) {
    if (!orderId || !email) {
      const err = new Error('orderId and email are required for payment intent');
      err.code = 'PAYMENT_INTENT_INVALID';
      throw err;
    }
    return this.adapter.create({
      intentId: `gpi_${crypto.randomUUID()}`,
      provider: 'mollie',
      orderId: String(orderId),
      amount: normalizeAmount(amount),
      currency: String(currency).toUpperCase(),
      emailHash: normalizeEmailHash(email),
    });
  }

  async bind(intentId, providerPaymentId) {
    return this.adapter.bindProviderPayment(intentId, providerPaymentId);
  }

  async get(intentId) {
    return this.adapter.get(intentId);
  }

  async verify({ intentId, providerPaymentId, orderId, amount, currency = 'EUR', email }) {
    const intent = await this.get(intentId);
    if (!intent) return { ok: false, reason: 'intent_not_found' };
    if (intent.providerPaymentId !== String(providerPaymentId)) return { ok: false, reason: 'provider_payment_mismatch' };
    if (intent.orderId !== String(orderId)) return { ok: false, reason: 'order_mismatch' };
    if (intent.amount !== normalizeAmount(amount)) return { ok: false, reason: 'amount_mismatch' };
    if (intent.currency !== String(currency).toUpperCase()) return { ok: false, reason: 'currency_mismatch' };
    if (intent.emailHash !== normalizeEmailHash(email)) return { ok: false, reason: 'email_mismatch' };
    return { ok: true, intent };
  }
}

function createPaymentIntentRuntime(env = process.env) {
  const backend = (env.GPAY_PAYMENT_STATE_BACKEND || 'local').trim().toLowerCase();
  if (backend === 'local') return new LocalPaymentIntentRuntime();
  if (backend !== 'postgres') {
    const err = new Error(`Unsupported GPAY_PAYMENT_STATE_BACKEND: ${backend}`);
    err.code = 'PAYMENT_STATE_BACKEND_UNSUPPORTED';
    throw err;
  }
  if (!env.GPAY_POSTGRES_URL || !env.GPAY_POSTGRES_URL.trim()) {
    const err = new Error('GPAY_POSTGRES_URL is required for postgres payment intent backend');
    err.code = 'PAYMENT_STATE_CONFIG_MISSING';
    throw err;
  }
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: env.GPAY_POSTGRES_URL.trim(), max: 10 });
  return new SharedPaymentIntentRuntime(new PostgresPaymentIntentAdapter(pool));
}

module.exports = {
  LocalPaymentIntentRuntime,
  SharedPaymentIntentRuntime,
  createPaymentIntentRuntime,
};
