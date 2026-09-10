const { PaymentStateAdapter, assertForwardTransition } = require('./payment-state-adapter');

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS gpay_payment_state (
  provider TEXT NOT NULL,
  provider_payment_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  version BIGINT NOT NULL DEFAULT 0,
  processed_at TIMESTAMPTZ NOT NULL,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (provider, provider_payment_id),
  CHECK (stage IN ('RECEIVED','PROVIDER_VERIFIED','EFFECTS_PREPARED','COMMITTED'))
);
`;

class PostgresPaymentStateAdapter extends PaymentStateAdapter {
  constructor(pool) {
    super();
    this.pool = pool;
  }

  async ensureSchema() {
    await this.pool.query(SCHEMA_SQL);
  }

  async get(provider, providerPaymentId) {
    const { rows } = await this.pool.query(
      'SELECT provider, provider_payment_id, stage, version, processed_at, data FROM gpay_payment_state WHERE provider=$1 AND provider_payment_id=$2',
      [provider, providerPaymentId]
    );
    return rows[0] || null;
  }

  async reserve(record) {
    const { provider, providerPaymentId, processedAt, data = {} } = record;
    const { rows } = await this.pool.query(
      `INSERT INTO gpay_payment_state(provider, provider_payment_id, stage, version, processed_at, data)
       VALUES($1,$2,'RECEIVED',0,$3,$4::jsonb)
       ON CONFLICT(provider, provider_payment_id) DO NOTHING
       RETURNING provider, provider_payment_id, stage, version, processed_at, data`,
      [provider, providerPaymentId, processedAt, JSON.stringify(data)]
    );
    if (rows[0]) return { created: true, record: rows[0] };
    return { created: false, record: await this.get(provider, providerPaymentId) };
  }

  async compareAndSetStage(provider, providerPaymentId, expectedVersion, nextStage, patch = {}) {
    const current = await this.get(provider, providerPaymentId);
    if (!current) {
      const err = new Error('Payment state record not found');
      err.code = 'PAYMENT_STATE_NOT_FOUND';
      throw err;
    }
    assertForwardTransition(current.stage, nextStage);

    const { rows } = await this.pool.query(
      `UPDATE gpay_payment_state
       SET stage=$4, version=version+1, data=data || $5::jsonb, updated_at=NOW()
       WHERE provider=$1 AND provider_payment_id=$2 AND version=$3
       RETURNING provider, provider_payment_id, stage, version, processed_at, data`,
      [provider, providerPaymentId, expectedVersion, nextStage, JSON.stringify(patch)]
    );

    if (!rows[0]) {
      const err = new Error('Payment state compare-and-set conflict');
      err.code = 'PAYMENT_STATE_CAS_CONFLICT';
      throw err;
    }
    return rows[0];
  }
}

function createPostgresPaymentStateAdapter(env = process.env) {
  const connectionString = env.GPAY_POSTGRES_URL;
  if (!connectionString || !connectionString.trim()) {
    const err = new Error('GPAY_POSTGRES_URL is required for postgres payment state backend');
    err.code = 'PAYMENT_STATE_CONFIG_MISSING';
    throw err;
  }

  let Pool;
  try {
    ({ Pool } = require('pg'));
  } catch {
    const err = new Error('PostgreSQL backend selected but pg package is not installed');
    err.code = 'PAYMENT_STATE_DRIVER_MISSING';
    throw err;
  }

  const pool = new Pool({ connectionString: connectionString.trim(), max: 10 });
  return new PostgresPaymentStateAdapter(pool);
}

module.exports = { SCHEMA_SQL, PostgresPaymentStateAdapter, createPostgresPaymentStateAdapter };
