const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const evidence = require('../../scripts/run-g-finance-sandbox-write-proof');
const openBanking = require('../routes/openbanking');

const env = { ...process.env };

try {
  const paymentId = '12345678-1234-4234-8234-123456789abc';
  const record = evidence.buildEvidenceRecord(
    paymentId,
    '2026-09-09T16:30:00.000Z'
  );

  assert.equal(record.rail, 'G_BANK');
  assert.equal(record.evidence_type, 'WRITE_READBACK');
  assert.equal(record.environment, 'SANDBOX');
  assert.equal(record.readback_match, true);
  assert.equal(record.value_moved, false);
  assert.equal(record.creditor_settlement_proven, false);
  assert.equal(record.verified_value_flow, false);
  assert.match(record.record_sha256, /^[0-9a-f]{64}$/);
  assert.equal(evidence.validateEvidenceRecord(record), true);

  assert.throws(
    () => evidence.validateEvidenceRecord({ ...record, verified_value_flow: true }),
    /must not claim settlement or value flow/
  );

  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'g-finance-004-'));
  const output = path.join(temp, 'evidence.json');
  evidence.writeEvidenceRecord(record, output);
  assert.equal(fs.existsSync(output), true);
  assert.equal(
    JSON.parse(fs.readFileSync(output, 'utf8')).record_sha256,
    record.record_sha256
  );
  assert.throws(() => evidence.writeEvidenceRecord(record, output), /already exists/);

  process.env.TRUELAYER_ENV = 'sandbox';
  process.env.G_BANK_ENABLE_LIVE = 'false';
  let status = openBanking._test.gFinanceStatusContract();
  assert.equal(status.schema_version, 'g-finance-runtime/1.0');
  assert.equal(status.rail, 'G_BANK');
  assert.equal(status.environment, 'SANDBOX');
  assert.equal(status.authenticated, false);
  assert.equal(status.external_actions_enabled, false);
  assert.equal(status.write_verified, false);
  assert.equal(status.value_transfer_verified, false);
  assert.equal(status.verified_value_flow, false);

  process.env.TRUELAYER_ENV = 'live';
  process.env.G_BANK_ENABLE_LIVE = 'true';
  status = openBanking._test.gFinanceStatusContract();
  assert.equal(status.environment, 'PRODUCTION');
  assert.equal(status.authenticated, false);
  assert.equal(status.value_transfer_verified, false);
  // Missing live release gates/configuration must keep the execution flag closed.
  assert.equal(status.external_actions_enabled, false);

  console.log('G-FINANCE-004 GPAY tests: PASS');
} finally {
  for (const key of Object.keys(process.env)) {
    if (!(key in env)) delete process.env[key];
  }
  Object.assign(process.env, env);
}
