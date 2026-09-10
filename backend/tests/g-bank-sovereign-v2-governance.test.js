'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { evaluatePaymentPolicy } = require('../g-bank-sovereign-v2/risk-policy');
const { approvalPayload } = require('../g-bank-sovereign-v2/authority');
const { createGovernanceProof, verifyGovernanceProof } = require('../g-bank-sovereign-v2/governance');
const { snapshotState, writeCheckpoint, verifyCheckpoint } = require('../g-bank-sovereign-v2/checkpoint');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T06:30:00.000Z');

function prepared(amount = 60000) {
  const instruction = {
    source_account_id: 'G:CUSTOMER:001',
    instruction_sha256: H('1'),
    beneficiary_binding_sha256: H('2'),
    amount_minor: amount,
    currency: 'EUR',
    scheme: 'SCT_INST',
  };
  const body = {
    schema: 'g-bank-sovereign-prepared-payment/v2',
    instruction,
    compliance_proof: { proof_sha256: H('3') },
    iso20022: { document_sha256: H('4'), message_type: 'pacs.008.001.08' },
    prepared_at: new Date(NOW).toISOString(),
  };
  return Object.freeze({ ...body, preparation_sha256: sha256(canonicalJson(body)) });
}

function schemeEvidence(p) {
  return {
    result: 'PASS',
    scheme: p.instruction.scheme,
    message_type: p.iso20022.message_type,
    message_sha256: p.iso20022.document_sha256,
    validation_level: 'EXTERNAL_SCHEME_VALIDATED',
    validator_binding_sha256: H('5'),
    validation_receipt_sha256: H('6'),
    observed_at: new Date(NOW).toISOString(),
  };
}

function keyPair(operator_id, role) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    operator_id,
    role,
    status: 'ACTIVE',
    public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey,
  };
}

function sign(operator, payload) {
  return {
    operator_id: operator.operator_id,
    payload_sha256: payload.payload_sha256,
    signed_at: new Date(NOW).toISOString(),
    signature_base64: crypto.sign(null, Buffer.from(payload.payload_sha256, 'utf8'), operator.privateKey).toString('base64'),
  };
}

(() => {
  const p = prepared();
  const validation = schemeEvidence(p);
  const policy = {
    currency: 'EUR',
    max_single_amount_minor: 100000,
    max_daily_amount_minor: 150000,
    high_value_threshold_minor: 50000,
    high_value_quorum: 2,
    normal_quorum: 1,
    allowed_schemes: ['SCT_INST'],
    blocked_beneficiary_hashes: [],
    policy_epoch: 7,
  };
  const prior = [{
    event: 'SOVEREIGN_SETTLEMENT_VERIFIED',
    value_moved: true,
    source_account_id: 'G:CUSTOMER:001',
    amount_minor: 40000,
    currency: 'EUR',
    observed_at: new Date(NOW - 60000).toISOString(),
  }];
  const risk = evaluatePaymentPolicy({ prepared: p, policy, receiptRows: prior, now: NOW });
  assert.equal(risk.decision, 'ALLOW');
  assert.equal(risk.required_quorum, 2);
  assert.equal(risk.projected_daily_minor, 100000);

  const senior = keyPair('OPS:SENIOR:01', 'SENIOR_APPROVER');
  const approver = keyPair('OPS:APPROVER:02', 'APPROVER');
  const authoritySet = {
    authority_epoch: 11,
    operators: [senior, approver].map(({ privateKey, ...pub }) => pub),
  };
  const key = 'idem-governance-0001';
  const payload = approvalPayload({
    prepared: p,
    schemeValidationEvidence: validation,
    riskDecision: risk,
    idempotencyKey: key,
    authorityEpoch: 11,
  });
  const signatures = [sign(senior, payload), sign(approver, payload)];
  const proof = createGovernanceProof({
    prepared: p,
    schemeValidationEvidence: validation,
    idempotencyKey: key,
    policy,
    authoritySet,
    signatures,
    receiptRows: prior,
    now: NOW,
  });
  assert.equal(proof.required_quorum, 2);
  assert.equal(proof.quorum_proof.accepted_operators.length, 2);
  assert.equal(verifyGovernanceProof(proof, { prepared: p, now: NOW }), true);

  assert.throws(() => createGovernanceProof({
    prepared: p,
    schemeValidationEvidence: validation,
    idempotencyKey: key,
    policy: { ...policy, max_daily_amount_minor: 90000 },
    authoritySet,
    signatures,
    receiptRows: prior,
    now: NOW,
  }), /payment_policy_denied/);

  assert.throws(() => createGovernanceProof({
    prepared: p,
    schemeValidationEvidence: validation,
    idempotencyKey: key,
    policy,
    authoritySet,
    signatures: [sign(approver, payload)],
    receiptRows: prior,
    now: NOW,
  }), /approval_quorum_not_met/);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-checkpoint-'));
  const paths = {
    accountRegistryPath: path.join(root, 'accounts.json'),
    ledgerPath: path.join(root, 'ledger.jsonl'),
    receiptsPath: path.join(root, 'receipts.jsonl'),
    executionsDir: path.join(root, 'executions'),
  };
  fs.mkdirSync(paths.executionsDir);
  fs.writeFileSync(paths.accountRegistryPath, '{"accounts":[]}\n');
  fs.writeFileSync(paths.ledgerPath, '{"sequence":1}\n');
  fs.writeFileSync(paths.receiptsPath, '{"sequence":1}\n');
  fs.writeFileSync(path.join(paths.executionsDir, 'a.json'), '{"state":"SETTLED"}\n');

  const checkpoint = snapshotState({ ...paths, now: NOW });
  const checkpointFile = path.join(root, 'checkpoint.json');
  writeCheckpoint(checkpointFile, checkpoint);
  assert.equal(verifyCheckpoint(checkpoint, paths).verified, true);
  fs.appendFileSync(paths.ledgerPath, '{"tamper":true}\n');
  const verification = verifyCheckpoint(checkpoint, paths);
  assert.equal(verification.verified, false);
  assert.equal(verification.checks.ledger, false);
  assert.equal(verification.checks.state_root, false);

  console.log('G-BANK sovereign v2 governance/recovery tests: PASS');
})();
