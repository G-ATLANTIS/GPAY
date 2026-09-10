const { normalizeAmount, normalizeEmailHash } = require('./payment-intent-store');
const { PostgresPaymentEffectLedger } = require('./payment-effect-ledger');

function normalizeStageRow(row) {
  if (!row) return null;
  return {
    provider: row.provider,
    providerPaymentId: row.provider_payment_id,
    stage: row.stage,
    version: Number(row.version || 0),
    processedAt: row.processed_at instanceof Date ? row.processed_at.toISOString() : row.processed_at,
    data: row.data || {},
  };
}

async function prepareVerifiedPaymentTransaction({
  pool,
  provider = 'mollie',
  providerPaymentId,
  intentId,
  orderId,
  amount,
  currency = 'EUR',
  email,
  effectData = {},
  injectFailureAfterEffects = false,
}) {
  if (!pool || typeof pool.connect !== 'function') {
    const err = new Error('PostgreSQL pool is required for atomic payment preparation');
    err.code = 'PAYMENT_TX_POOL_REQUIRED';
    throw err;
  }

  const canonicalAmount = normalizeAmount(amount);
  const canonicalCurrency = String(currency).toUpperCase();
  const emailHash = normalizeEmailHash(email);
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const intentResult = await client.query(
      `SELECT intent_id, provider, provider_payment_id, order_id, amount, currency, email_hash, status
       FROM gpay_payment_intent
       WHERE intent_id=$1
       FOR UPDATE`,
      [intentId]
    );
    const intent = intentResult.rows[0];
    if (!intent) {
      const err = new Error('Payment intent not found during atomic preparation');
      err.code = 'PAYMENT_TX_INTENT_NOT_FOUND';
      throw err;
    }
    if (intent.provider !== provider || intent.provider_payment_id !== String(providerPaymentId)) {
      const err = new Error('Payment intent provider binding mismatch');
      err.code = 'PAYMENT_TX_INTENT_PROVIDER_MISMATCH';
      throw err;
    }
    if (intent.order_id !== String(orderId) || intent.amount !== canonicalAmount || intent.currency !== canonicalCurrency || intent.email_hash !== emailHash) {
      const err = new Error('Payment intent provenance mismatch');
      err.code = 'PAYMENT_TX_INTENT_PROVENANCE_MISMATCH';
      throw err;
    }

    const now = new Date().toISOString();
    await client.query(
      `INSERT INTO gpay_payment_state(provider, provider_payment_id, stage, version, processed_at, data)
       VALUES($1,$2,'RECEIVED',0,$3,$4::jsonb)
       ON CONFLICT(provider, provider_payment_id) DO NOTHING`,
      [provider, providerPaymentId, now, JSON.stringify({ processingStartedAt: now })]
    );

    const stateResult = await client.query(
      `SELECT provider, provider_payment_id, stage, version, processed_at, data
       FROM gpay_payment_state
       WHERE provider=$1 AND provider_payment_id=$2
       FOR UPDATE`,
      [provider, providerPaymentId]
    );
    let state = stateResult.rows[0];
    if (!state) {
      const err = new Error('Payment state missing during atomic preparation');
      err.code = 'PAYMENT_TX_STATE_MISSING';
      throw err;
    }

    if (state.stage === 'RECEIVED') {
      const advanced = await client.query(
        `UPDATE gpay_payment_state
         SET stage='PROVIDER_VERIFIED', version=version+1,
             data=data || $3::jsonb, updated_at=NOW()
         WHERE provider=$1 AND provider_payment_id=$2 AND version=$4
         RETURNING provider, provider_payment_id, stage, version, processed_at, data`,
        [
          provider,
          providerPaymentId,
          JSON.stringify({ intentId, orderId: String(orderId), amount: canonicalAmount, currency: canonicalCurrency }),
          state.version,
        ]
      );
      if (!advanced.rows[0]) {
        const err = new Error('Atomic payment-state compare-and-set conflict');
        err.code = 'PAYMENT_STATE_CAS_CONFLICT';
        throw err;
      }
      state = advanced.rows[0];
    } else if (!['PROVIDER_VERIFIED', 'EFFECTS_PREPARED', 'COMMITTED'].includes(state.stage)) {
      const err = new Error(`Unexpected payment stage: ${state.stage}`);
      err.code = 'PAYMENT_TX_STAGE_INVALID';
      throw err;
    }

    const effectLedger = new PostgresPaymentEffectLedger(client);
    for (const effectType of ['reward', 'invoice', 'gcoin-intent']) {
      await effectLedger.prepare(provider, providerPaymentId, effectType, {
        intentId,
        ...(effectData[effectType] || {}),
      });
    }

    if (injectFailureAfterEffects) {
      const err = new Error('Injected transactional rollback');
      err.code = 'PAYMENT_TX_INJECTED_FAILURE';
      throw err;
    }

    await client.query('COMMIT');
    return { state: normalizeStageRow(state), intentVerified: true, effectsReserved: true };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch {}
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { prepareVerifiedPaymentTransaction, normalizeStageRow };
