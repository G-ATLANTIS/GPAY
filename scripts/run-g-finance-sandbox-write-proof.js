require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const official = require('./test-official-truelayer-stack');

const DEFAULT_OUT = path.resolve(
  process.cwd(),
  '.secrets',
  'evidence',
  'g-finance-sandbox-write-readback.json'
);

function requireSandboxSafety() {
  if ((process.env.TRUELAYER_ENV || 'sandbox').toLowerCase() !== 'sandbox') {
    throw new Error('G-FINANCE sandbox write proof refuses non-sandbox TrueLayer environments.');
  }
  if (process.env.G_BANK_ENABLE_LIVE === 'true') {
    throw new Error('G-FINANCE sandbox write proof refuses G_BANK_ENABLE_LIVE=true.');
  }
}

function canonicalEvidencePayload(record) {
  return JSON.stringify({
    schema_version: record.schema_version,
    rail: record.rail,
    evidence_type: record.evidence_type,
    provider: record.provider,
    environment: record.environment,
    source: record.source,
    observed_at: record.observed_at,
    external_id: record.external_id,
    readback_match: record.readback_match,
    provider_generator_verified: record.provider_generator_verified,
    provider_webhook_router_verified: record.provider_webhook_router_verified,
    local_webhook_delivery_verified: record.local_webhook_delivery_verified,
    signed_webhook_acceptance_verified: record.signed_webhook_acceptance_verified,
    payment_created_in_sandbox: record.payment_created_in_sandbox,
    value_moved: record.value_moved,
    creditor_settlement_proven: record.creditor_settlement_proven,
    verified_value_flow: record.verified_value_flow
  });
}

function buildEvidenceRecord(paymentId, observedAt = new Date().toISOString()) {
  if (!/^[0-9a-f-]{36}$/i.test(String(paymentId || ''))) {
    throw new Error('Verified sandbox payment ID must be a UUID.');
  }

  const record = {
    schema_version: 'g-finance-write-readback/1.0',
    rail: 'G_BANK',
    evidence_type: 'WRITE_READBACK',
    provider: 'truelayer',
    environment: 'SANDBOX',
    source: 'GPAY:official-truelayer-stack',
    observed_at: observedAt,
    external_id: String(paymentId).toLowerCase(),
    readback_match: true,

    // test-official-truelayer-stack.run() returns only after all four checks pass.
    provider_generator_verified: true,
    provider_webhook_router_verified: true,
    local_webhook_delivery_verified: true,
    signed_webhook_acceptance_verified: true,

    payment_created_in_sandbox: true,
    value_moved: false,
    creditor_settlement_proven: false,
    verified_value_flow: false
  };

  record.record_sha256 = crypto
    .createHash('sha256')
    .update(canonicalEvidencePayload(record))
    .digest('hex');

  return record;
}

function validateEvidenceRecord(record) {
  if (record.schema_version !== 'g-finance-write-readback/1.0') {
    throw new Error('unsupported evidence schema');
  }
  if (record.rail !== 'G_BANK' || record.evidence_type !== 'WRITE_READBACK') {
    throw new Error('invalid G-FINANCE evidence classification');
  }
  if (record.environment !== 'SANDBOX') {
    throw new Error('write/readback evidence must remain sandbox-bound');
  }
  if (
    record.readback_match !== true ||
    record.provider_generator_verified !== true ||
    record.provider_webhook_router_verified !== true ||
    record.local_webhook_delivery_verified !== true ||
    record.signed_webhook_acceptance_verified !== true
  ) {
    throw new Error('incomplete sandbox write/readback proof');
  }
  if (
    record.value_moved !== false ||
    record.creditor_settlement_proven !== false ||
    record.verified_value_flow !== false
  ) {
    throw new Error('sandbox write/readback must not claim settlement or value flow');
  }

  const expected = crypto
    .createHash('sha256')
    .update(canonicalEvidencePayload(record))
    .digest('hex');

  const supplied = String(record.record_sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) throw new Error('record_sha256_invalid');
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(supplied, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error('record_sha256_mismatch');
  }
  return true;
}

function writeEvidenceRecord(record, outputPath = DEFAULT_OUT, { force = false } = {}) {
  validateEvidenceRecord(record);
  const resolved = path.resolve(outputPath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  if (fs.existsSync(resolved) && !force) {
    throw new Error('Evidence file already exists. Use --force only after intentional re-verification.');
  }
  fs.writeFileSync(resolved, JSON.stringify(record, null, 2) + '\n', {
    mode: 0o600,
    flag: force ? 'w' : 'wx'
  });
  return resolved;
}

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : null;
}

async function run() {
  requireSandboxSafety();

  const paymentId = await official.run();
  const record = buildEvidenceRecord(paymentId);
  const output = writeEvidenceRecord(
    record,
    arg('--out') || DEFAULT_OUT,
    { force: process.argv.includes('--force') }
  );

  console.log('G-FINANCE sandbox WRITE_READBACK evidence: VERIFIED');
  console.log('Payment ID:', record.external_id);
  console.log('Evidence:', output);
  console.log('Record SHA-256:', record.record_sha256);
  console.log('Value moved: FALSE');
  console.log('Creditor settlement proven: FALSE');
  console.log('Verified value flow: FALSE');
  return record;
}

if (require.main === module) {
  run().catch(err => {
    console.error('G-FINANCE sandbox WRITE_READBACK evidence: BLOCKED');
    console.error(err.message || err);
    process.exit(2);
  });
}

module.exports = {
  DEFAULT_OUT,
  requireSandboxSafety,
  canonicalEvidencePayload,
  buildEvidenceRecord,
  validateEvidenceRecord,
  writeEvidenceRecord,
  run
};
