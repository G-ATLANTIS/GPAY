const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const proof = require('../../scripts/run-g-finance-provider-auth-proof');

const env = { ...process.env };

try {
  const result = {
    provider: 'truelayer',
    environment: 'sandbox',
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
    '2026-09-09T16:55:00.000Z'
  );

  assert.equal(record.schema_version, 'g-finance-provider-auth/1.0');
  assert.equal(record.rail, 'G_BANK');
  assert.equal(record.evidence_type, 'AUTHENTICATION_READBACK');
  assert.equal(record.environment, 'SANDBOX');
  assert.equal(record.provider_authentication_verified, true);
  assert.equal(record.access_token_obtained, true);
  assert.equal(record.request_signature_accepted, true);
  assert.equal(record.provider_http_status, 204);
  assert.equal(record.payment_created, false);
  assert.equal(record.value_moved, false);
  assert.equal(record.verified_write, false);
  assert.equal(record.verified_value_flow, false);
  assert.match(record.record_sha256, /^[0-9a-f]{64}$/);
  assert.equal(proof.validateEvidenceRecord(record), true);

  assert.throws(
    () => proof.buildEvidenceRecord({ ...result, provider_http_status: 401 }),
    /did not accept/
  );
  assert.throws(
    () => proof.buildEvidenceRecord({ ...result, payment_created: true }),
    /must not create payments/
  );
  assert.throws(
    () => proof.validateEvidenceRecord({ ...record, value_moved: true }),
    /non-payment and non-value-moving/
  );
  assert.throws(
    () => proof.validateEvidenceRecord({ ...record, provider_http_status: 200 }),
    /incomplete provider-auth proof/
  );
  assert.throws(
    () => proof.validateEvidenceRecord({ ...record, source: 'tampered' }),
    /record_sha256_mismatch/
  );

  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'g-finance-auth-'));
  const output = path.join(temp, 'auth.json');
  proof.writeEvidenceRecord(record, output);
  assert.equal(fs.existsSync(output), true);
  assert.equal(
    JSON.parse(fs.readFileSync(output, 'utf8')).record_sha256,
    record.record_sha256
  );
  assert.throws(
    () => proof.writeEvidenceRecord(record, output),
    /already exists/
  );

  process.env.TRUELAYER_ENV = 'sandbox';
  process.env.G_BANK_ENABLE_LIVE = 'false';
  process.env.G_BANK_ENABLE_PROVIDER_PROBE = 'true';
  process.env.G_BANK_PROVIDER_PROBE_SECRET = 'x'.repeat(32);
  assert.equal(proof.requireSandboxSafety(), 'x'.repeat(32));

  process.env.TRUELAYER_ENV = 'live';
  assert.throws(() => proof.requireSandboxSafety(), /refuses non-sandbox/);

  process.env.TRUELAYER_ENV = 'sandbox';
  process.env.G_BANK_ENABLE_PROVIDER_PROBE = 'false';
  assert.throws(() => proof.requireSandboxSafety(), /ENABLE_PROVIDER_PROBE/);

  console.log('G-FINANCE-009 provider-auth tests: PASS');
} finally {
  for (const key of Object.keys(process.env)) {
    if (!(key in env)) delete process.env[key];
  }
  Object.assign(process.env, env);
}
