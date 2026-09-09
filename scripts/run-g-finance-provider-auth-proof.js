require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const openBanking = require('../backend/routes/openbanking');

const DEFAULT_OUT = path.resolve(
  process.cwd(),
  '.secrets',
  'evidence',
  'g-finance-provider-auth.json'
);

function requireSandboxSafety() {
  if ((process.env.TRUELAYER_ENV || 'sandbox').toLowerCase() !== 'sandbox') {
    throw new Error('G-FINANCE provider-auth proof currently refuses non-sandbox TrueLayer environments.');
  }
  if (process.env.G_BANK_ENABLE_LIVE === 'true') {
    throw new Error('G-FINANCE provider-auth proof refuses G_BANK_ENABLE_LIVE=true.');
  }
  if (process.env.G_BANK_ENABLE_PROVIDER_PROBE !== 'true') {
    throw new Error('G_BANK_ENABLE_PROVIDER_PROBE=true is required for the non-payment provider-auth proof.');
  }
  const secret = process.env.G_BANK_PROVIDER_PROBE_SECRET || '';
  if (secret.length < 32) {
    throw new Error('G_BANK_PROVIDER_PROBE_SECRET must contain at least 32 characters.');
  }
  return secret;
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
    proof_scope: record.proof_scope,
    probe_endpoint: record.probe_endpoint,
    provider_authentication_verified: record.provider_authentication_verified,
    access_token_obtained: record.access_token_obtained,
    request_signature_accepted: record.request_signature_accepted,
    provider_http_status: record.provider_http_status,
    payment_created: record.payment_created,
    bank_authorization_started: record.bank_authorization_started,
    value_moved: record.value_moved,
    verified_write: record.verified_write,
    verified_value_flow: record.verified_value_flow
  });
}

function buildEvidenceRecord(result, observedAt = new Date().toISOString()) {
  if (!result || result.provider !== 'truelayer') {
    throw new Error('TrueLayer provider readiness result is required.');
  }
  if (String(result.environment || '').toLowerCase() !== 'sandbox') {
    throw new Error('Provider-auth proof must remain sandbox-bound.');
  }
  if (result.access_token_obtained !== true) {
    throw new Error('TrueLayer access token was not obtained.');
  }
  if (result.request_signature_accepted !== true || result.provider_http_status !== 204) {
    throw new Error('TrueLayer did not accept the signed non-payment readiness request.');
  }
  if (
    result.payment_created !== false ||
    result.bank_authorization_started !== false ||
    result.value_moved !== false ||
    result.verified_write !== false ||
    result.verified_value_flow !== false
  ) {
    throw new Error('Provider-auth proof must not create payments, move value, or claim write/value verification.');
  }

  const record = {
    schema_version: 'g-finance-provider-auth/1.0',
    rail: 'G_BANK',
    evidence_type: 'AUTHENTICATION_READBACK',
    provider: 'truelayer',
    environment: 'SANDBOX',
    source: 'GPAY:provider-readiness',
    observed_at: observedAt,
    proof_scope: 'NON_PAYMENT_AUTHENTICATION',
    probe_endpoint: '/test-signature',
    provider_authentication_verified: true,
    access_token_obtained: true,
    request_signature_accepted: true,
    provider_http_status: 204,
    payment_created: false,
    bank_authorization_started: false,
    value_moved: false,
    verified_write: false,
    verified_value_flow: false
  };

  record.record_sha256 = crypto
    .createHash('sha256')
    .update(canonicalEvidencePayload(record))
    .digest('hex');

  return record;
}

function validateEvidenceRecord(record) {
  if (record.schema_version !== 'g-finance-provider-auth/1.0') {
    throw new Error('unsupported provider-auth evidence schema');
  }
  if (record.rail !== 'G_BANK' || record.evidence_type !== 'AUTHENTICATION_READBACK') {
    throw new Error('invalid provider-auth evidence classification');
  }
  if (record.provider !== 'truelayer' || record.environment !== 'SANDBOX') {
    throw new Error('provider-auth evidence must be TrueLayer SANDBOX');
  }
  if (
    record.proof_scope !== 'NON_PAYMENT_AUTHENTICATION' ||
    record.probe_endpoint !== '/test-signature' ||
    record.provider_authentication_verified !== true ||
    record.access_token_obtained !== true ||
    record.request_signature_accepted !== true ||
    record.provider_http_status !== 204
  ) {
    throw new Error('incomplete provider-auth proof');
  }
  if (
    record.payment_created !== false ||
    record.bank_authorization_started !== false ||
    record.value_moved !== false ||
    record.verified_write !== false ||
    record.verified_value_flow !== false
  ) {
    throw new Error('provider-auth proof must remain non-payment and non-value-moving');
  }

  const observed = Date.parse(record.observed_at);
  if (!Number.isFinite(observed)) {
    throw new Error('observed_at_invalid');
  }

  const expected = crypto
    .createHash('sha256')
    .update(canonicalEvidencePayload(record))
    .digest('hex');

  const supplied = String(record.record_sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) {
    throw new Error('record_sha256_invalid');
  }
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
    throw new Error('Provider-auth evidence already exists. Use --force only after an intentional fresh probe.');
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
  const secret = requireSandboxSafety();
  const result = await openBanking._test.performProviderReadiness(undefined, secret);
  const record = buildEvidenceRecord(result);
  const output = writeEvidenceRecord(
    record,
    arg('--out') || DEFAULT_OUT,
    { force: process.argv.includes('--force') }
  );

  console.log('G-FINANCE provider AUTHENTICATION_READBACK evidence: VERIFIED');
  console.log('Environment: SANDBOX');
  console.log('Access token obtained: TRUE');
  console.log('Signed /test-signature accepted: TRUE');
  console.log('Provider HTTP status: 204');
  console.log('Evidence:', output);
  console.log('Record SHA-256:', record.record_sha256);
  console.log('Payment created: FALSE');
  console.log('Value moved: FALSE');
  console.log('Verified write: FALSE');
  console.log('Verified value flow: FALSE');
  return record;
}

if (require.main === module) {
  run().catch(err => {
    console.error('G-FINANCE provider AUTHENTICATION_READBACK evidence: BLOCKED');
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
