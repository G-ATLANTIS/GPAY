const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function stateDir() {
  return process.env.GPAY_STATE_DIR || path.join(process.cwd(), 'state');
}

function storeFile() {
  return path.join(stateDir(), 'payment-intents.json');
}

function ensureStore() {
  fs.mkdirSync(stateDir(), { recursive: true });
  if (!fs.existsSync(storeFile())) {
    fs.writeFileSync(storeFile(), JSON.stringify({ intents: {} }, null, 2), { mode: 0o600 });
  }
}

function readStore() {
  ensureStore();
  return JSON.parse(fs.readFileSync(storeFile(), 'utf8'));
}

function atomicWrite(store) {
  ensureStore();
  const target = storeFile();
  const tmp = `${target}.${process.pid}.${Date.now()}.tmp`;
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.writeFileSync(fd, JSON.stringify(store, null, 2));
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, target);
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function normalizeEmailHash(email) {
  return sha256(String(email).trim().toLowerCase());
}

function normalizeAmount(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    const err = new Error('Payment intent amount must be positive');
    err.code = 'PAYMENT_INTENT_AMOUNT_INVALID';
    throw err;
  }
  return numeric.toFixed(2);
}

function createPaymentIntent({ orderId, amount, currency = 'EUR', email }) {
  if (!orderId || !email) {
    const err = new Error('orderId and email are required for payment intent');
    err.code = 'PAYMENT_INTENT_INVALID';
    throw err;
  }
  const intentId = `gpi_${crypto.randomUUID()}`;
  const now = new Date().toISOString();
  const record = {
    intentId,
    provider: 'mollie',
    providerPaymentId: null,
    orderId: String(orderId),
    amount: normalizeAmount(amount),
    currency: String(currency).toUpperCase(),
    emailHash: normalizeEmailHash(email),
    status: 'CREATED',
    createdAt: now,
    updatedAt: now,
  };
  const store = readStore();
  store.intents[intentId] = record;
  atomicWrite(store);
  return record;
}

function bindProviderPayment(intentId, providerPaymentId) {
  if (!providerPaymentId) {
    const err = new Error('providerPaymentId is required');
    err.code = 'PAYMENT_INTENT_PROVIDER_ID_MISSING';
    throw err;
  }
  const store = readStore();
  const current = store.intents[intentId];
  if (!current) {
    const err = new Error('Payment intent not found');
    err.code = 'PAYMENT_INTENT_NOT_FOUND';
    throw err;
  }
  if (current.providerPaymentId && current.providerPaymentId !== providerPaymentId) {
    const err = new Error('Payment intent provider binding is immutable');
    err.code = 'PAYMENT_INTENT_REBIND_DENIED';
    throw err;
  }
  if (current.providerPaymentId === providerPaymentId) return current;
  const next = {
    ...current,
    providerPaymentId: String(providerPaymentId),
    status: 'PROVIDER_BOUND',
    updatedAt: new Date().toISOString(),
  };
  store.intents[intentId] = next;
  atomicWrite(store);
  return next;
}

function getPaymentIntent(intentId) {
  if (!intentId) return null;
  return readStore().intents[intentId] || null;
}

function verifyPaymentIntent({ intentId, providerPaymentId, orderId, amount, currency = 'EUR', email }) {
  const intent = getPaymentIntent(intentId);
  if (!intent) return { ok: false, reason: 'intent_not_found' };
  if (intent.providerPaymentId !== String(providerPaymentId)) return { ok: false, reason: 'provider_payment_mismatch' };
  if (intent.orderId !== String(orderId)) return { ok: false, reason: 'order_mismatch' };
  if (intent.amount !== normalizeAmount(amount)) return { ok: false, reason: 'amount_mismatch' };
  if (intent.currency !== String(currency).toUpperCase()) return { ok: false, reason: 'currency_mismatch' };
  if (intent.emailHash !== normalizeEmailHash(email)) return { ok: false, reason: 'email_mismatch' };
  return { ok: true, intent };
}

module.exports = {
  sha256,
  normalizeEmailHash,
  normalizeAmount,
  createPaymentIntent,
  bindProviderPayment,
  getPaymentIntent,
  verifyPaymentIntent,
};
