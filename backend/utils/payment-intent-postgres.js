const { normalizeAmount, normalizeEmailHash } = require('./payment-intent-store');

const PAYMENT_INTENT_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS gpay_payment_intent (
  intent_id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  provider_payment_id TEXT NULL,
  order_id TEXT NOT NULL,
  amount TEXT NOT NULL,
  currency TEXT NOT NULL,
  email_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  version BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (status IN ('CREATED','PROVIDER_BOUND')),
  UNIQUE (provider, provider_payment_id)
);
`;

function normalizeRecord(row) {
  if (!row) return null;
  return {
    intentId: row.intent_id,
    provider: row.provider,
    providerPaymentId: row.provider_payment_id,
    orderId: row.order_id,
    amount: row.amount,
    currency: row.currency,
    emailHash: row.email_hash,
    status: row.status,
    version: Number(row.version || 0),
    createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
    updatedAt: row.updated_at instanceof Date ? row.updated_at.toISOString() : row.updated_at,
  };
}

class PostgresPaymentIntentAdapter {
  constructor(pool) {
    this.pool = pool;
  }

  async ensureSchema() {
    await this.pool.query(PAYMENT_INTENT_SCHEMA_SQL);
  }

  async create(record) {
    const { rows } = await this.pool.query(
      `INSERT INTO gpay_payment_intent(
         intent_id, provider, provider_payment_id, order_id, amount, currency, email_hash, status
       ) VALUES($1,$2,NULL,$3,$4,$5,$6,'CREATED')
       RETURNING *`,
      [
        record.intentId,
        record.provider,
        String(record.orderId),
        normalizeAmount(record.amount),
        String(record.currency || 'EUR').toUpperCase(),
        record.emailHash || normalizeEmailHash(record.email),
      ]
    );
    return normalizeRecord(rows[0]);
  }

  async get(intentId) {
    const { rows } = await this.pool.query(
      'SELECT * FROM gpay_payment_intent WHERE intent_id=$1',
      [intentId]
    );
    return normalizeRecord(rows[0]);
  }

  async bindProviderPayment(intentId, providerPaymentId) {
    const current = await this.get(intentId);
    if (!current) {
      const err = new Error('Payment intent not found');
      err.code = 'PAYMENT_INTENT_NOT_FOUND';
      throw err;
    }
    if (current.providerPaymentId === String(providerPaymentId)) return current;
    if (current.providerPaymentId) {
      const err = new Error('Payment intent provider binding is immutable');
      err.code = 'PAYMENT_INTENT_REBIND_DENIED';
      throw err;
    }

    const { rows } = await this.pool.query(
      `UPDATE gpay_payment_intent
       SET provider_payment_id=$2, status='PROVIDER_BOUND', version=version+1, updated_at=NOW()
       WHERE intent_id=$1 AND provider_payment_id IS NULL
       RETURNING *`,
      [intentId, String(providerPaymentId)]
    );
    if (!rows[0]) {
      const err = new Error('Payment intent binding contention');
      err.code = 'PAYMENT_INTENT_BIND_CONFLICT';
      throw err;
    }
    return normalizeRecord(rows[0]);
  }
}

module.exports = {
  PAYMENT_INTENT_SCHEMA_SQL,
  PostgresPaymentIntentAdapter,
  normalizeRecord,
};
