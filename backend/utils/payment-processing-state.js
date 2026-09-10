const fs = require('fs');
const path = require('path');

const STAGES = Object.freeze({
  RECEIVED: 10,
  PROVIDER_VERIFIED: 20,
  EFFECTS_PREPARED: 30,
  COMMITTED: 40,
});

function stateDir() {
  return process.env.GPAY_STATE_DIR || path.join(process.cwd(), 'state');
}

function stateFile() {
  return path.join(stateDir(), 'payment-processing-state.json');
}

function ensureStore() {
  fs.mkdirSync(stateDir(), { recursive: true });
  if (!fs.existsSync(stateFile())) {
    fs.writeFileSync(stateFile(), JSON.stringify({ payments: {} }, null, 2));
  }
}

function readStore() {
  ensureStore();
  return JSON.parse(fs.readFileSync(stateFile(), 'utf8'));
}

function atomicWrite(store) {
  ensureStore();
  const target = stateFile();
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

function key(provider, providerPaymentId) {
  if (!provider || !providerPaymentId) throw new Error('provider and providerPaymentId are required');
  return `${provider}:${providerPaymentId}`;
}

function getPaymentState(provider, providerPaymentId) {
  const store = readStore();
  return store.payments[key(provider, providerPaymentId)] || null;
}

function beginPayment(provider, providerPaymentId, now = new Date().toISOString()) {
  const store = readStore();
  const k = key(provider, providerPaymentId);
  if (store.payments[k]) return { created: false, state: store.payments[k] };
  const state = {
    provider,
    providerPaymentId,
    stage: 'RECEIVED',
    stageRank: STAGES.RECEIVED,
    processingStartedAt: now,
    processedAt: now,
    updatedAt: now,
  };
  store.payments[k] = state;
  atomicWrite(store);
  return { created: true, state };
}

function advancePayment(provider, providerPaymentId, stage, patch = {}, now = new Date().toISOString()) {
  if (!Object.prototype.hasOwnProperty.call(STAGES, stage)) {
    const err = new Error(`Unknown payment stage: ${stage}`);
    err.code = 'PAYMENT_STAGE_INVALID';
    throw err;
  }

  const store = readStore();
  const k = key(provider, providerPaymentId);
  const current = store.payments[k];
  if (!current) {
    const err = new Error('Payment processing state does not exist');
    err.code = 'PAYMENT_STATE_MISSING';
    throw err;
  }

  const nextRank = STAGES[stage];
  if (nextRank < current.stageRank) {
    const err = new Error(`Payment stage rollback denied: ${current.stage} -> ${stage}`);
    err.code = 'PAYMENT_STAGE_ROLLBACK_DENIED';
    throw err;
  }

  if (nextRank === current.stageRank) {
    return { changed: false, state: current };
  }

  const next = {
    ...current,
    ...patch,
    provider: current.provider,
    providerPaymentId: current.providerPaymentId,
    processedAt: current.processedAt,
    processingStartedAt: current.processingStartedAt,
    stage,
    stageRank: nextRank,
    updatedAt: now,
  };
  store.payments[k] = next;
  atomicWrite(store);
  return { changed: true, state: next };
}

module.exports = {
  STAGES,
  getPaymentState,
  beginPayment,
  advancePayment,
};
