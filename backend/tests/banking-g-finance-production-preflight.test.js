const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const proof = require('../../scripts/run-g-finance-production-preflight');

const env = { ...process.env };

try {
  const result = {
    provider: 'truelayer',
    environment: 'live',
    access_token_obtained: true,
    request_signature_accepted: true,
    provider_http_status: 204,
    payment_created: false,
    bank_authorization_started: false,
    value_moved: false,
    verified_write: false,
    verified_value_flow: false
  };

  const record = proof.buildEvidenceRecord(
    result,
    '2026-09-09T17:05:00.000Z'
  );

  assert.equal(record.schema_version, 'g-finance-production-preflight/1.0');
  assert.equal(record.environment, 'PRODUCTION');
  assert.equal(record.evidence_type, 'AUTHENTICATION_READBACK');
  assert.equal(record.provider_authentication_verified, true);
  assert.equal(record.access_token_obtained, true);
  assert.equal(record.request_signature_accepted, true);
  assert.equal(record.provider_http_status, 204);
  assert.equal(record.live_execution_enabled, false);
  assert.equal(record.external_actions_enabled, false);
  assert.equal(record.payment_endpoint_called, false);
  assert.equal(record.payment_created, false);
  assert.equal(record.value_moved, false);
  assert.equal(record.go_live_promotion_performed, false);
  assert.match(record.record_sha256, /^[0-9a-f]{64}$/);
  assert.equal(proof.validateEvidenceRecord(record), true);

  assert.throws(
    () => proof.buildEvidenceRecord({ ...result, environment: 'sandbox' }),
    /live endpoints/
  );
  assert.throws(
    () => proof.buildEvidenceRecord({ ...result, provider_http_status: 401 }),
    /did not accept/
  );
  assert.throws(
    () => proof.buildEvidenceRecord({ ...result, payment_created: true }),
    /must not create payments/
  );
  assert.throws(
    () => proof.validateEvidenceRecord({ ...record, external_actions_enabled: true }),
    /external_actions_enabled=false/
  );
  assert.throws(
    () => proof.validateEvidenceRecord({ ...record, payment_endpoint_called: true }),
    /payment_endpoint_called=false/
  );
  assert.throws(
    () => proof.validateEvidenceRecord({ ...record, source: 'tampered' }),
    /record_sha256_mismatch/
  );

  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'g-finance-010-'));
  const output = path.join(temp, 'preflight.json');
  proof.writeEvidenceRecord(record, output);
  assert.equal(fs.existsSync(output), true);
  assert.throws(
    () => proof.writeEvidenceRecord(record, output),
    /already exists/
  );

  process.env.TRUELAYER_ENV = 'live';
  process.env.G_BANK_ENABLE_LIVE = 'false';
  process.env.G_BANK_ENABLE_PROVIDER_PROBE = 'true';
  process.env.G_BANK_PROVIDER_PROBE_SECRET = 'x'.repeat(32);
  assert.equal(proof.requireProductionPreflightSafety(), 'x'.repeat(32));

  process.env.TRUELAYER_ENV = 'sandbox';
  assert.throws(
    () => proof.requireProductionPreflightSafety(),
    /requires TRUELAYER_ENV=live/
  );

  process.env.TRUELAYER_ENV = 'live';
  process.env.G_BANK_ENABLE_LIVE = 'true';
  assert.throws(
    () => proof.requireProductionPreflightSafety(),
    /refuses G_BANK_ENABLE_LIVE=true/
  );

  console.log('G-FINANCE-010 production preflight tests: PASS');
} finally {
  for (const key of Object.keys(process.env)) {
    if (!(key in env)) delete process.env[key];
  }
  Object.assign(process.env, env);
}
