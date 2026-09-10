'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { settlementOperationBinding } = require('../g-bank-sovereign-v2/settlement-operation-binding');

const H = c => c.repeat(64);
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-cli-v2-'));
const marker = path.join(root, 'transport-loaded.marker');
const transport = path.join(root, 'transport.js');
fs.writeFileSync(transport, `'use strict';\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)}, 'LOADED');\nmodule.exports = {};\n`, { mode: 0o600 });

const script = path.resolve(__dirname, '../../scripts/g-bank-sovereign-v2.js');
const dummy = path.join(root, 'does-not-need-to-exist.json');
const challengeStore = path.join(root, 'runtime-ha-challenges.jsonl');
const challengeOut = path.join(root, 'runtime-ha-challenge.json');
const preparedPath = path.join(root, 'prepared.json');
const promotionPath = path.join(root, 'promotion.json');
const idempotencyKey = '00000000-0000-4000-8000-000000000001';
const prepared = { iso20022: { document_sha256: H('1') }, instruction: { instruction_sha256: H('2') } };
const promotion = { certificate_sha256: H('3') };
fs.writeFileSync(preparedPath, JSON.stringify(prepared) + '\n', { mode: 0o600 });
fs.writeFileSync(promotionPath, JSON.stringify(promotion) + '\n', { mode: 0o600 });
const expectedOperation = settlementOperationBinding({
  message_sha256: H('1'), instruction_sha256: H('2'), idempotency_key: idempotencyKey, promotion_certificate_sha256: H('3'),
});

const baseArgs = [
  script, 'execute',
  '--prepared', dummy,
  '--validation', dummy,
  '--approval', dummy,
  '--signatures', dummy,
  '--idempotency-key', idempotencyKey,
  '--readiness', dummy,
  '--promotion', dummy,
  '--promotion-sha256', 'a'.repeat(64),
];
const baseEnv = { ...process.env, G_BANK_SETTLEMENT_TRANSPORT_MODULE: transport };

(() => {
  const result = spawnSync(process.execPath, [
    script, 'issue-ha-challenge', '--challenge-store', challengeStore,
    '--prepared', preparedPath, '--promotion', promotionPath, '--idempotency-key', idempotencyKey,
    '--out', challengeOut, '--ttl-ms', '30000',
  ], { env: baseEnv, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const parsed = JSON.parse(result.stdout);
  const challenge = JSON.parse(fs.readFileSync(challengeOut, 'utf8'));
  assert.equal(parsed.state, 'HA_RUNTIME_CHALLENGE_ISSUED');
  assert.match(challenge.nonce_sha256, /^[0-9a-f]{64}$/);
  assert.match(challenge.issue_record_sha256, /^[0-9a-f]{64}$/);
  assert.equal(challenge.operation_binding_sha256, expectedOperation.operation_binding_sha256);
  assert.equal(challenge.message_sha256, H('1'));
  assert.equal(challenge.instruction_sha256, H('2'));
  assert.equal(challenge.idempotency_key, idempotencyKey);
  assert.equal(challenge.promotion_certificate_sha256, H('3'));
  assert.equal(challenge.grants_external_rights, false);
  assert.equal(challenge.permits_value_movement_by_itself, false);
  assert.equal(fs.existsSync(marker), false, 'issuing an HA challenge must never load settlement transport');
})();

(() => {
  const badOut = path.join(root, 'must-not-exist.json');
  const result = spawnSync(process.execPath, [script, 'issue-ha-challenge', '--challenge-store', challengeStore, '--out', badOut], { env: baseEnv, encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--challenge-store --prepared --promotion --idempotency-key --out_required/);
  assert.equal(fs.existsSync(badOut), false);
  assert.equal(fs.existsSync(marker), false);
})();

(() => {
  const result = spawnSync(process.execPath, baseArgs, { env: baseEnv, encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--promotion-signing-request --promotion-signature-evidence --promotion-signer-authority --promotion-signature-bundle --runtime-ha-attestation --runtime-ha-observer --runtime-ha-challenge-store_required/);
  assert.equal(fs.existsSync(marker), false, 'transport module must not load when promotion signature/quorum inputs are absent');
})();

(() => {
  const argsWithSingleSignerEvidence = [
    ...baseArgs,
    '--promotion-signing-request', dummy,
    '--promotion-signature-evidence', dummy,
  ];
  const result = spawnSync(process.execPath, argsWithSingleSignerEvidence, { env: baseEnv, encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--promotion-signer-authority --promotion-signature-bundle --runtime-ha-attestation --runtime-ha-observer --runtime-ha-challenge-store_required/);
  assert.equal(fs.existsSync(marker), false, 'single promotion signer evidence must not be enough to load transport');
})();

(() => {
  const argsWithPromotionQuorum = [
    ...baseArgs,
    '--promotion-signing-request', dummy,
    '--promotion-signature-evidence', dummy,
    '--promotion-signer-authority', dummy,
    '--promotion-signature-bundle', dummy,
  ];
  const result = spawnSync(process.execPath, argsWithPromotionQuorum, { env: baseEnv, encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--runtime-ha-attestation --runtime-ha-observer --runtime-ha-challenge-store_required/);
  assert.equal(fs.existsSync(marker), false, 'transport module must not load when runtime HA arguments are absent');
})();

(() => {
  const argsAlmostComplete = [
    ...baseArgs,
    '--promotion-signing-request', dummy,
    '--promotion-signature-evidence', dummy,
    '--promotion-signer-authority', dummy,
    '--promotion-signature-bundle', dummy,
    '--runtime-ha-attestation', dummy,
    '--runtime-ha-observer', dummy,
  ];
  const result = spawnSync(process.execPath, argsAlmostComplete, { env: baseEnv, encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--runtime-ha-challenge-store_required/);
  assert.equal(fs.existsSync(marker), false, 'transport module must not load when runtime HA challenge store is absent');
})();

console.log('G-BANK sovereign v2 promotion-quorum CLI contract tests: PASS');
