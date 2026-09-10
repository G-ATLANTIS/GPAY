const STAGES = Object.freeze(['RECEIVED', 'PROVIDER_VERIFIED', 'EFFECTS_PREPARED', 'COMMITTED']);

function stageIndex(stage) {
  const index = STAGES.indexOf(stage);
  if (index < 0) {
    const err = new Error(`Unknown payment stage: ${stage}`);
    err.code = 'PAYMENT_STAGE_INVALID';
    throw err;
  }
  return index;
}

function assertForwardTransition(currentStage, nextStage) {
  const current = stageIndex(currentStage);
  const next = stageIndex(nextStage);
  if (next < current) {
    const err = new Error(`Payment stage rollback denied: ${currentStage} -> ${nextStage}`);
    err.code = 'PAYMENT_STAGE_ROLLBACK_DENIED';
    throw err;
  }
  return true;
}

class PaymentStateAdapter {
  async get(_provider, _providerPaymentId) {
    throw new Error('PaymentStateAdapter.get not implemented');
  }

  async reserve(_record) {
    throw new Error('PaymentStateAdapter.reserve not implemented');
  }

  async compareAndSetStage(_provider, _providerPaymentId, _expectedVersion, _nextStage, _patch = {}) {
    throw new Error('PaymentStateAdapter.compareAndSetStage not implemented');
  }
}

function loadConfiguredPaymentStateAdapter(env = process.env) {
  const backend = (env.GPAY_PAYMENT_STATE_BACKEND || 'local').trim().toLowerCase();
  if (backend === 'local') return null;
  if (backend === 'postgres') {
    const { createPostgresPaymentStateAdapter } = require('./payment-state-postgres');
    return createPostgresPaymentStateAdapter(env);
  }
  const err = new Error(`Unsupported GPAY_PAYMENT_STATE_BACKEND: ${backend}`);
  err.code = 'PAYMENT_STATE_BACKEND_UNSUPPORTED';
  throw err;
}

module.exports = {
  STAGES,
  stageIndex,
  assertForwardTransition,
  PaymentStateAdapter,
  loadConfiguredPaymentStateAdapter,
};
