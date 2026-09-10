const fs = require('fs');
const path = require('path');

const VALID_EFFECT_TYPES = new Set(['reward', 'invoice', 'email', 'gcoin-intent']);
const VALID_STATUSES = new Set(['PREPARED', 'COMPLETED']);

function effectId(provider, providerPaymentId, effectType) {
  if (!VALID_EFFECT_TYPES.has(effectType)) {
    const err = new Error(`Unsupported payment effect type: ${effectType}`);
    err.code = 'PAYMENT_EFFECT_TYPE_INVALID';
    throw err;
  }
  return `${provider}:${providerPaymentId}:${effectType}`;
}

function stateDir() {
  return process.env.GPAY_STATE_DIR || path.join(process.cwd(), 'state');
}

function localFile() {
  return path.join(stateDir(), 'payment-effects.json');
}

function ensureLocalStore() {
  fs.mkdirSync(stateDir(), { recursive: true });
  if (!fs.existsSync(localFile())) {
    fs.writeFileSync(localFile(), JSON.stringify({ effects: {} }, null, 2), { mode: 0o600 });
  }
}

function readLocalStore() {
  ensureLocalStore();
  return JSON.parse(fs.readFileSync(localFile(), 'utf8'));
}

function writeLocalStore(store) {
  ensureLocalStore();
  const target = localFile();
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

class LocalPaymentEffectLedger {
  async ensureReady() {}

  async get(provider, providerPaymentId, effectType) {
    const id = effectId(provider, providerPaymentId, effectType);
    return readLocalStore().effects[id] || null;
  }

  async prepare(provider, providerPaymentId, effectType, data = {}) {
    const id = effectId(provider, providerPaymentId, effectType);
    const store = readLocalStore();
    const current = store.effects[id];
    if (current) return { created: false, record: current };
    const now = new Date().toISOString();
    const record = {
      effectId: id,
      provider,
      providerPaymentId,
      effectType,
      status: 'PREPARED',
      data,
      createdAt: now,
      updatedAt: now,
    };
    store.effects[id] = record;
    writeLocalStore(store);
    return { created: true, record };
  }

  async complete(provider, providerPaymentId, effectType, data = {}) {
    const id = effectId(provider, providerPaymentId, effectType);
    const store = readLocalStore();
    const current = store.effects[id];
    if (!current) {
      const err = new Error('Payment effect must be prepared before completion');
      err.code = 'PAYMENT_EFFECT_NOT_PREPARED';
      throw err;
    }
    if (current.status === 'COMPLETED') return { changed: false, record: current };
    const record = {
      ...current,
      status: 'COMPLETED',
      data: { ...current.data, ...data },
      updatedAt: new Date().toISOString(),
    };
    store.effects[id] = record;
    writeLocalStore(store);
    return { changed: true, record };
  }
}

const POSTGRES_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS gpay_payment_effect (
  effect_id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  provider_payment_id TEXT NOT NULL,
  effect_type TEXT NOT NULL,
  status TEXT NOT NULL,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(provider, provider_payment_id, effect_type),
  CHECK (effect_type IN ('reward','invoice','email','gcoin-intent')),
  CHECK (status IN ('PREPARED','COMPLETED'))
);
`;

class PostgresPaymentEffectLedger {
  constructor(pool) {
    this.pool = pool;
  }

  async ensureReady() {
    await this.pool.query(POSTGRES_SCHEMA_SQL);
  }

  async get(provider, providerPaymentId, effectType) {
    effectId(provider, providerPaymentId, effectType);
    const { rows } = await this.pool.query(
      `SELECT effect_id, provider, provider_payment_id, effect_type, status, data, created_at, updated_at
       FROM gpay_payment_effect
       WHERE provider=$1 AND provider_payment_id=$2 AND effect_type=$3`,
      [provider, providerPaymentId, effectType]
    );
    return rows[0] || null;
  }

  async prepare(provider, providerPaymentId, effectType, data = {}) {
    const id = effectId(provider, providerPaymentId, effectType);
    const { rows } = await this.pool.query(
      `INSERT INTO gpay_payment_effect(effect_id, provider, provider_payment_id, effect_type, status, data)
       VALUES($1,$2,$3,$4,'PREPARED',$5::jsonb)
       ON CONFLICT(provider, provider_payment_id, effect_type) DO NOTHING
       RETURNING effect_id, provider, provider_payment_id, effect_type, status, data, created_at, updated_at`,
      [id, provider, providerPaymentId, effectType, JSON.stringify(data)]
    );
    if (rows[0]) return { created: true, record: rows[0] };
    return { created: false, record: await this.get(provider, providerPaymentId, effectType) };
  }

  async complete(provider, providerPaymentId, effectType, data = {}) {
    effectId(provider, providerPaymentId, effectType);
    const { rows } = await this.pool.query(
      `UPDATE gpay_payment_effect
       SET status='COMPLETED', data=data || $4::jsonb, updated_at=NOW()
       WHERE provider=$1 AND provider_payment_id=$2 AND effect_type=$3 AND status='PREPARED'
       RETURNING effect_id, provider, provider_payment_id, effect_type, status, data, created_at, updated_at`,
      [provider, providerPaymentId, effectType, JSON.stringify(data)]
    );
    if (rows[0]) return { changed: true, record: rows[0] };
    const current = await this.get(provider, providerPaymentId, effectType);
    if (!current) {
      const err = new Error('Payment effect must be prepared before completion');
      err.code = 'PAYMENT_EFFECT_NOT_PREPARED';
      throw err;
    }
    if (current.status === 'COMPLETED') return { changed: false, record: current };
    const err = new Error('Payment effect completion conflict');
    err.code = 'PAYMENT_EFFECT_CONFLICT';
    throw err;
  }
}

function createPaymentEffectLedger(env = process.env) {
  const backend = (env.GPAY_PAYMENT_STATE_BACKEND || 'local').trim().toLowerCase();
  if (backend === 'local') return new LocalPaymentEffectLedger();
  if (backend !== 'postgres') {
    const err = new Error(`Unsupported payment effect backend: ${backend}`);
    err.code = 'PAYMENT_EFFECT_BACKEND_UNSUPPORTED';
    throw err;
  }
  const connectionString = env.GPAY_POSTGRES_URL;
  if (!connectionString || !connectionString.trim()) {
    const err = new Error('GPAY_POSTGRES_URL is required for postgres payment effect ledger');
    err.code = 'PAYMENT_EFFECT_CONFIG_MISSING';
    throw err;
  }
  let Pool;
  try {
    ({ Pool } = require('pg'));
  } catch {
    const err = new Error('PostgreSQL payment effect backend requires pg');
    err.code = 'PAYMENT_EFFECT_DRIVER_MISSING';
    throw err;
  }
  return new PostgresPaymentEffectLedger(new Pool({ connectionString: connectionString.trim(), max: 10 }));
}

module.exports = {
  VALID_EFFECT_TYPES,
  VALID_STATUSES,
  effectId,
  POSTGRES_SCHEMA_SQL,
  LocalPaymentEffectLedger,
  PostgresPaymentEffectLedger,
  createPaymentEffectLedger,
};
