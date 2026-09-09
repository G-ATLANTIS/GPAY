require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const openBanking = require('../backend/routes/openbanking');

const DEFAULT_OUT = path.resolve(
  process.cwd(),
  '.secrets',
  'evidence',
  'g-finance-production-preflight.json'
);

function requireProductionPreflightSafety() {
  if ((process.env.TRUELAYER_ENV || '').toLowerCase() !== 'live') {
    throw new Error('G-FINANCE production preflight requires TRUELAYER_ENV=live.');
  }
  if (process.env.G_BANK_ENABLE_LIVE === 'true') {
    throw new Error('G-FINANCE production preflight refuses G_BANK_ENABLE_LIVE=true.');
  }
  const clientId = String(process.env.TRUELAYER_CLIENT_ID || '');
  if (clientId.startsWith('sandbox-')) {
    throw new Error('G-FINANCE production preflight refuses a sandbox-prefixed TrueLayer client_id on live endpoints.');
  }
  if (process.env.G_BANK_ENABLE_PROVIDER_PROBE !== 'true') {
    throw new Error('G_BANK_ENABLE_PROVIDER_PROBE=true is required for production preflight.');
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
    provider_authentication_verified: record.provider_authentication_verified,
    access_token_obtained: record.access_token_obtained,
    request_signature_accepted: record.request_signature_accepted,
    provider_http_status: record.provider_http_status,
    live_execution_enabled: record.live_execution_enabled,
    external_actions_enabled: record.external_actions_enabled,
    payment_endpoint_called: record.payment_endpoint_called,
    payment_created: record.payment_created,
    bank_authorization_started: record.bank_authorization_started,
    value_moved: record.value_moved,
    verified_write: record.verified_write,
    verified_value_flow: record.verified_value_flow,
    go_live_promotion_performed: record.go_live_promotion_performed
  });
}

function buildEvidenceRecord(result, observedAt = new Date().toISOString()) {
  if (!result || result.provider !== 'truelayer') {
    throw new Error('TrueLayer provider readiness result is required.');
  }
  if (String(result.environment || '').toLowerCase() !== 'live') {
    throw new Error('Production preflight result must come from TrueLayer live endpoints.');
  }
  if (result.access_token_obtained !== true) {
    throw new Error('Production access token was not obtained.');
  }
  if (result.request_signature_accepted !== true || result.provider_http_status !== 204) {
    throw new Error('TrueLayer production did not accept the signed non-payment readiness request.');
  }
  if (
    result.payment_created !== false ||
    result.bank_authorization_started !== false ||
    result.value_moved !== false ||
    result.verified_write !== false ||
    result.verified_value_flow !== false
  ) {
    throw new Error('Production preflight must not create payments, move value, or claim write/value verification.');
  }

  const record = {
    schema_version: 'g-finance-production-preflight/1.0',
    rail: 'G_BANK',
    evidence_type: 'AUTHENTICATION_READBACK',
    provider: 'truelayer',
    environment: 'PRODUCTION',
    source: 'GPAY:production-provider-readiness',
    observed_at: observedAt,
    proof_scope: 'PRODUCTION_NON_PAYMENT_PREFLIGHT',
    provider_authentication_verified: true,
    access_token_obtained: true,
    request_signature_accepted: true,
    provider_http_status: 204,
    live_execution_enabled: false,
    external_actions_enabled: false,
    payment_endpoint_called: false,
    payment_created: false,
    bank_authorization_started: false,
    value_moved: false,
    verified_write: false,
    verified_value_flow: false,
    go_live_promotion_performed: false
  };

  record.record_sha256 = crypto
    .createHash('sha256')
    .update(canonicalEvidencePayload(record))
    .digest('hex');

  return record;
}

function validateEvidenceRecord(record) {
  if (record.schema_version !== 'g-finance-production-preflight/1.0') {
    throw new Error('unsupported production preflight schema');
  }
  if (record.rail !== 'G_BANK' || record.evidence_type !== 'AUTHENTICATION_READBACK') {
    throw new Error('invalid production preflight classification');
  }
  if (record.provider !== 'truelayer' || record.environment !== 'PRODUCTION') {
    throw new Error('production preflight must be TrueLayer PRODUCTION');
  }
  if (record.proof_scope !== 'PRODUCTION_NON_PAYMENT_PREFLIGHT') {
    throw new Error('invalid production preflight scope');
  }
  if (
    record.provider_authentication_verified !== true ||
    record.access_token_obtained !== true ||
    record.request_signature_accepted !== true ||
    record.provider_http_status !== 204
  ) {
    throw new Error('incomplete production provider-auth proof');
  }

  const requiredFalse = [
    'live_execution_enabled',
    'external_actions_enabled',
    'payment_endpoint_called',
    'payment_created',
    'bank_authorization_started',
    'value_moved',
    'verified_write',
    'verified_value_flow',
    'go_live_promotion_performed'
  ];
  for (const key of requiredFalse) {
    if (record[key] !== false) {
      throw new Error(`production preflight requires ${key}=false`);
    }
  }

  const observed = Date.parse(record.observed_at);
  if (!Number.isFinite(observed)) throw new Error('observed_at_invalid');

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
    throw new Error('Production preflight evidence already exists. Use --force only after a fresh production probe.');
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
  const secret = requireProductionPreflightSafety();

  // performProviderReadiness uses the environment-selected auth/API endpoints.
  // With TRUELAYER_ENV=live and G_BANK_ENABLE_LIVE=false this is a bounded,
  // non-payment production authentication/signature check only.
  const result = await openBanking._test.performProviderReadiness(undefined, secret);
  const record = buildEvidenceRecord(result);
  const output = writeEvidenceRecord(
    record,
    arg('--out') || DEFAULT_OUT,
    { force: process.argv.includes('--force') }
  );

  console.log('G-FINANCE production preflight: VERIFIED');
  console.log('Environment: PRODUCTION');
  console.log('Access token obtained: TRUE');
  console.log('Signed non-payment readiness request accepted: TRUE');
  console.log('Provider HTTP status: 204');
  console.log('Evidence:', output);
  console.log('Record SHA-256:', record.record_sha256);
  console.log('Live execution enabled: FALSE');
  console.log('External actions enabled: FALSE');
  console.log('Payment endpoint called: FALSE');
  console.log('Payment created: FALSE');
  console.log('Value moved: FALSE');
  console.log('Go-live promotion performed: FALSE');
  return record;
}

if (require.main === module) {
  run().catch(err => {
    const providerError = err.response?.data?.error || '';
    const providerDescription = err.response?.data?.error_description || '';

    console.error('G-FINANCE production preflight: BLOCKED');

    if (providerError === 'invalid_scope') {
      console.error('BLOCKER_CLASS = LIVE_PAYMENTS_SCOPE_NOT_ENABLED_OR_WRONG_LIVE_APP');
      console.error('REQUESTED_SCOPE = payments');
      console.error('PROVIDER_ERROR = invalid_scope');
      if (providerDescription) {
        console.error('PROVIDER_DESCRIPTION =', providerDescription);
      }
      console.error(
        'NEXT_ACTION = Verify the TrueLayer Console LIVE app has Payments enabled and that the loaded live client_id/client_secret belong to that same live app.'
      );
    } else {
      console.error(providerError || providerDescription || err.message || err);
    }

    console.error('Payment endpoint called: FALSE');
    console.error('Payment created: FALSE');
    console.error('Value moved: FALSE');
    console.error('Go-live promotion performed: FALSE');
    process.exit(2);
  });
}

module.exports = {
  DEFAULT_OUT,
  requireProductionPreflightSafety,
  canonicalEvidencePayload,
  buildEvidenceRecord,
  validateEvidenceRecord,
  writeEvidenceRecord,
  run
};
