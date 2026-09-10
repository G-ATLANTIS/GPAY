'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { SovereignLedger } = require('../g-bank-sovereign-v2/ledger');
const { AccountRegistry } = require('../g-bank-sovereign-v2/accounts');
const { DirectSettlementAdapter } = require('../g-bank-sovereign-v2/direct-settlement');
const { GBankSovereignCore } = require('../g-bank-sovereign-v2/sovereign-core');
const { createSovereignApproval, verifySovereignApproval } = require('../g-bank-sovereign-v2/approval');
const { evaluatePaymentPolicy } = require('../g-bank-sovereign-v2/risk-policy');
const { approvalPayload } = require('../g-bank-sovereign-v2/authority');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T06:30:00.000Z');

function env() {
  return {
    G_BANK_ENABLE_LIVE: 'true',
    G_BANK_EXTERNAL_ACTIONS_ENABLED: 'true',
    G_BANK_DIRECT_SETTLEMENT_ENABLED: 'true',
    G_BANK_GOVERNANCE_REQUIRED: 'true',
    G_BANK_SIMULATED_LIVE_SUCCESS: 'false',
    G_BANK_SETTLEMENT_AUTHORIZATION_SHA256: H('a'),
    G_BANK_SOVEREIGN_APPROVAL_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef',
    G_BANK_BIC: 'ABNANL2A',
    G_BANK_OUTBOUND_SUSPENSE_ACCOUNT: 'G:SUSPENSE:OUTBOUND',
    G_BANK_SETTLEMENT_OUT_ACCOUNT: 'G:SETTLEMENT:OUTBOUND',
  };
}

function evidence(now = NOW) {
  const observed_at = new Date(now).toISOString();
  return {
    sanctions_screen: { result: 'CLEAR', observed_at, evidence_sha256: H('b') },
    aml_gate: { result: 'PASS', observed_at, evidence_sha256: H('c') },
    verification_of_payee: { result: 'MATCH', observed_at, evidence_sha256: H('d') },
  };
}

function instruction(id = 'PAY0000000000001') {
  return {
    instruction_id: id,
    message_id: `MSG${id.slice(3)}`,
    end_to_end_id: `E2E${id.slice(3)}`,
    source_account_id: 'G:CUSTOMER:001',
    amount_minor: 1000,
    currency: 'EUR',
    scheme: 'SCT_INST',
    debtor: { name: 'G Customer', address: { country: 'NL', town: 'Amsterdam', street: 'Teststraat', building_number: '1', post_code: '1000AA' } },
    debtor_iban: 'NL91ABNA0417164300',
    creditor: { name: 'Example Merchant', address: { country: 'NL', town: 'Utrecht', street: 'Voorbeeldweg', building_number: '2', post_code: '3500AA' } },
    creditor_iban: 'NL39RABO0300065264',
    creditor_agent_bic: 'RABONL2U',
    remittance: 'G-BANK sovereign v2 test',
    requested_at: new Date(NOW).toISOString(),
  };
}

function setup(transport) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-v2-'));
  const e = env();
  const accounts = new AccountRegistry(path.join(root, 'accounts.json'));
  const ledger = new SovereignLedger(path.join(root, 'ledger.jsonl'));
  for (const account of [
    { account_id: 'G:FUNDING:GENESIS', type: 'TREASURY', iban: null, owner: H('1') },
    { account_id: 'G:CUSTOMER:001', type: 'CUSTOMER', iban: 'NL91ABNA0417164300', owner: H('2') },
    { account_id: 'G:SUSPENSE:OUTBOUND', type: 'SUSPENSE', iban: null, owner: H('3') },
    { account_id: 'G:SETTLEMENT:OUTBOUND', type: 'SETTLEMENT', iban: null, owner: H('4') },
  ]) accounts.register({ account_id: account.account_id, type: account.type, currency: 'EUR', iban: account.iban, owner_binding_sha256: account.owner });

  ledger.post({
    transaction_id: 'GENESIS-FUNDING-1',
    reference: 'TEST-FUNDING',
    entries: [
      { account_id: 'G:FUNDING:GENESIS', side: 'DEBIT', amount_minor: 10000, currency: 'EUR' },
      { account_id: 'G:CUSTOMER:001', side: 'CREDIT', amount_minor: 10000, currency: 'EUR' },
    ],
  });

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const operator = {
    operator_id: 'OPS:PRIMARY:01',
    role: 'SENIOR_APPROVER',
    status: 'ACTIVE',
    public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey,
  };
  const authoritySet = {
    authority_epoch: 1,
    operators: [{
      operator_id: operator.operator_id,
      role: operator.role,
      status: operator.status,
      public_key_pem: operator.public_key_pem,
    }],
  };
  const riskPolicy = {
    currency: 'EUR',
    max_single_amount_minor: 10000,
    max_daily_amount_minor: 50000,
    high_value_threshold_minor: 5000,
    high_value_quorum: 2,
    normal_quorum: 1,
    allowed_schemes: ['SCT_INST'],
    blocked_beneficiary_hashes: [],
    policy_epoch: 1,
  };

  const settlement = new DirectSettlementAdapter({ transport, env: e });
  const core = new GBankSovereignCore({
    accounts,
    ledger,
    settlement,
    riskPolicy,
    authoritySet,
    stateDir: path.join(root, 'state'),
    env: e,
  });
  return { root, e, accounts, ledger, core, riskPolicy, authoritySet, operator };
}

function schemeEvidence(prepared) {
  return {
    result: 'PASS',
    scheme: prepared.instruction.scheme,
    message_type: prepared.iso20022.message_type,
    message_sha256: prepared.iso20022.document_sha256,
    validation_level: 'EXTERNAL_SCHEME_VALIDATED',
    validator_binding_sha256: H('e'),
    validation_receipt_sha256: H('f'),
    observed_at: new Date(NOW).toISOString(),
  };
}

function authoritySignatures(s, prepared, validation, key) {
  const risk = evaluatePaymentPolicy({
    prepared,
    policy: s.riskPolicy,
    receiptRows: s.core.receipts.readAll(),
    now: NOW,
  });
  const payload = approvalPayload({
    prepared,
    schemeValidationEvidence: validation,
    riskDecision: risk,
    idempotencyKey: key,
    authorityEpoch: s.authoritySet.authority_epoch,
  });
  return [{
    operator_id: s.operator.operator_id,
    payload_sha256: payload.payload_sha256,
    signed_at: new Date(NOW).toISOString(),
    signature_base64: crypto.sign(null, Buffer.from(payload.payload_sha256, 'utf8'), s.operator.privateKey).toString('base64'),
  }];
}

(async () => {
  let submitCount = 0;
  const settledTransport = {
    async preflight() { return { environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST', settlement_system: 'TEST-DIRECT', external_receipt_sha256: H('5') }; },
    async submit() { submitCount += 1; return { submission_id: 'SUB-001', status: 'SUBMITTED', external_receipt_sha256: H('6'), provider_request_id: 'REQ-001' }; },
    async readback() { return { status: 'SETTLED', settlement_reference: 'SETTLE-001', external_receipt_sha256: H('7') }; },
  };
  const s = setup(settledTransport);
  const prepared = s.core.prepare({ rawInstruction: instruction(), complianceBundle: evidence(), now: NOW });
  assert.equal(prepared.iso20022.message_type, 'pacs.008.001.08');
  assert.match(prepared.iso20022.document, /<LclInstrm><Prtry>INST<\/Prtry><\/LclInstrm>/);
  const key = crypto.randomUUID();
  const validation = schemeEvidence(prepared);
  const approval = createSovereignApproval({ prepared, schemeValidationEvidence: validation, idempotencyKey: key, now: NOW }, s.e);
  const signatures = authoritySignatures(s, prepared, validation, key);
  const result = await s.core.execute({ prepared, schemeValidationEvidence: validation, approvalToken: approval, authoritySignatures: signatures, idempotencyKey: key, now: NOW });
  assert.equal(result.state, 'SETTLED');
  assert.equal(result.value_moved, true);
  assert.equal(result.verified_value_flow, true);
  assert.match(result.governance_proof_sha256, /^[0-9a-f]{64}$/);
  assert.equal(s.ledger.balance('G:CUSTOMER:001', 'EUR'), 9000);
  assert.equal(s.ledger.balance('G:SUSPENSE:OUTBOUND', 'EUR'), 0);
  assert.equal(s.ledger.balance('G:SETTLEMENT:OUTBOUND', 'EUR'), 1000);
  assert.equal(s.ledger.verify().verified, true);
  assert.equal(s.core.receipts.verify().valid, true);

  const replay = await s.core.execute({ prepared, schemeValidationEvidence: null, approvalToken: null, authoritySignatures: null, idempotencyKey: key, now: NOW + 86400000 });
  assert.equal(replay.result_sha256, result.result_sha256);
  assert.equal(submitCount, 1, 'terminal idempotent replay must not submit again');
  assert.equal(s.ledger.balance('G:CUSTOMER:001', 'EUR'), 9000);

  assert.throws(() => createSovereignApproval({ prepared, schemeValidationEvidence: validation, idempotencyKey: '', now: NOW }, s.e), /idempotency_key_required/);
  const wrongKey = crypto.randomUUID();
  assert.throws(() => verifySovereignApproval(approval, { prepared, schemeValidationEvidence: validation, idempotencyKey: wrongKey, now: NOW }, s.e), /approval_idempotency_mismatch/);
  const wrongValidation = { ...validation, validation_receipt_sha256: H('9') };
  assert.throws(() => verifySovereignApproval(approval, { prepared, schemeValidationEvidence: wrongValidation, idempotencyKey: key, now: NOW }, s.e), /approval_scheme_validation_receipt_mismatch/);

  const noSignatureSetup = setup(settledTransport);
  const noSigPrepared = noSignatureSetup.core.prepare({ rawInstruction: instruction('PAY0000000000009'), complianceBundle: evidence(), now: NOW });
  const noSigKey = crypto.randomUUID();
  const noSigValidation = schemeEvidence(noSigPrepared);
  const noSigApproval = createSovereignApproval({ prepared: noSigPrepared, schemeValidationEvidence: noSigValidation, idempotencyKey: noSigKey, now: NOW }, noSignatureSetup.e);
  await assert.rejects(noSignatureSetup.core.execute({ prepared: noSigPrepared, schemeValidationEvidence: noSigValidation, approvalToken: noSigApproval, authoritySignatures: [], idempotencyKey: noSigKey, now: NOW }), /approval_quorum_not_met/);

  let ambiguousSubmits = 0;
  const ambiguousTransport = {
    async preflight() { return { environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST', settlement_system: 'TEST-DIRECT', external_receipt_sha256: H('8') }; },
    async submit() { ambiguousSubmits += 1; throw new Error('transport_connection_dropped_after_submit'); },
    async readback() { throw new Error('should_not_be_called_without_submission_id'); },
  };
  const a = setup(ambiguousTransport);
  const p2 = a.core.prepare({ rawInstruction: instruction('PAY0000000000002'), complianceBundle: evidence(), now: NOW });
  const k2 = crypto.randomUUID();
  const v2 = schemeEvidence(p2);
  const ap2 = createSovereignApproval({ prepared: p2, schemeValidationEvidence: v2, idempotencyKey: k2, now: NOW }, a.e);
  const sig2 = authoritySignatures(a, p2, v2, k2);
  await assert.rejects(a.core.execute({ prepared: p2, schemeValidationEvidence: v2, approvalToken: ap2, authoritySignatures: sig2, idempotencyKey: k2, now: NOW }), /transport_connection_dropped_after_submit/);
  assert.equal(a.core.executions.read(k2).state, 'UNKNOWN');
  assert.equal(a.ledger.balance('G:CUSTOMER:001', 'EUR'), 9000, 'ambiguous submit keeps funds held');
  assert.equal(a.ledger.balance('G:SUSPENSE:OUTBOUND', 'EUR'), 1000);
  await assert.rejects(a.core.execute({ prepared: p2, schemeValidationEvidence: v2, approvalToken: ap2, authoritySignatures: sig2, idempotencyKey: k2, now: NOW }), /execution_exists_unknown_use_reconcile/);
  assert.equal(ambiguousSubmits, 1, 'ambiguous payment must never auto-resubmit');

  console.log('G-BANK sovereign v2 no-network safety tests: PASS');
})().catch(err => {
  console.error(err);
  process.exit(1);
});
