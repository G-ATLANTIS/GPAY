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
const { createTechnicalPromotionCertificate } = require('../g-bank-sovereign-v2/promotion-certificate');
const { normalizePromotionSignerAuthority } = require('../g-bank-sovereign-v2/promotion-signer-authority');
const { settlementOperationBinding } = require('../g-bank-sovereign-v2/settlement-operation-binding');
const { createSyntheticRuntimeObserver, configureSyntheticHAState, issueSyntheticRuntimeHAWitness } = require('./g-bank-sovereign-v2-runtime-ha-fixture');
const { createSyntheticPromotionSigner, configureSyntheticPromotionSignature } = require('./g-bank-sovereign-v2-promotion-signing-fixture');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T06:30:00.000Z');

function env() {
  return {
    G_BANK_ENABLE_LIVE: 'true', G_BANK_EXTERNAL_ACTIONS_ENABLED: 'true', G_BANK_DIRECT_SETTLEMENT_ENABLED: 'true',
    G_BANK_GOVERNANCE_REQUIRED: 'true', G_BANK_SIMULATED_LIVE_SUCCESS: 'false', G_BANK_SETTLEMENT_AUTHORIZATION_SHA256: H('a'),
    G_BANK_LEGAL_AUTHORIZATION_EVIDENCE_SHA256: H('b'), G_BANK_SCHEME_PARTICIPATION_EVIDENCE_SHA256: H('c'),
    G_BANK_SETTLEMENT_ACCESS_EVIDENCE_SHA256: H('d'), G_BANK_PRODUCTION_IDENTITY_EVIDENCE_SHA256: H('e'),
    G_BANK_PRUDENTIAL_AUDIT_SHA256: H('1'), G_BANK_OPERATIONAL_RESILIENCE_SHA256: H('2'), G_BANK_TREASURY_ASSESSMENT_SHA256: H('3'),
    G_BANK_CUSTOMER_MONITORING_AUDIT_SHA256: H('4'), G_BANK_RECOVERY_AUDIT_SHA256: H('5'), G_BANK_HA_AUDIT_SHA256: H('0'),
    G_BANK_HA_DEPLOYMENT_AUDIT_SHA256: H('f'), G_BANK_SOVEREIGN_APPROVAL_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef',
    G_BANK_BIC: 'ABNANL2A', G_BANK_OUTBOUND_SUSPENSE_ACCOUNT: 'G:SUSPENSE:OUTBOUND', G_BANK_SETTLEMENT_OUT_ACCOUNT: 'G:SETTLEMENT:OUTBOUND',
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
    instruction_id: id, message_id: `MSG${id.slice(3)}`, end_to_end_id: `E2E${id.slice(3)}`,
    source_account_id: 'G:CUSTOMER:001', amount_minor: 1000, currency: 'EUR', scheme: 'SCT_INST',
    debtor: { name: 'G Customer', address: { country: 'NL', town: 'Amsterdam', street: 'Teststraat', building_number: '1', post_code: '1000AA' } },
    debtor_iban: 'NL91ABNA0417164300',
    creditor: { name: 'Example Merchant', address: { country: 'NL', town: 'Utrecht', street: 'Voorbeeldweg', building_number: '2', post_code: '3500AA' } },
    creditor_iban: 'NL39RABO0300065264', creditor_agent_bic: 'RABONL2U', remittance: 'G-BANK sovereign v2 test', requested_at: new Date(NOW).toISOString(),
  };
}

function configureRuntimePromotion(root, e, policySha256, authoritySetSha256, runtimeObserver, promotionSigner, promotionSignerAuthority) {
  const fenceValidUntil = new Date(NOW + 240000).toISOString();
  const haState = configureSyntheticHAState({ env: e, state_root_sha256: H('6'), cluster_authority_root_sha256: H('8'), voter_journal_root_sha256: H('7'), fence_valid_until: fenceValidUntil, now: NOW });
  const evidenceBindings = {
    legal_authorization_evidence_sha256: e.G_BANK_LEGAL_AUTHORIZATION_EVIDENCE_SHA256,
    scheme_participation_evidence_sha256: e.G_BANK_SCHEME_PARTICIPATION_EVIDENCE_SHA256,
    settlement_access_evidence_sha256: e.G_BANK_SETTLEMENT_ACCESS_EVIDENCE_SHA256,
    production_identity_evidence_sha256: e.G_BANK_PRODUCTION_IDENTITY_EVIDENCE_SHA256,
    transport_preflight_receipt_sha256: H('9'), prudential_audit_sha256: e.G_BANK_PRUDENTIAL_AUDIT_SHA256,
    operational_resilience_sha256: e.G_BANK_OPERATIONAL_RESILIENCE_SHA256, treasury_assessment_sha256: e.G_BANK_TREASURY_ASSESSMENT_SHA256,
    customer_monitoring_audit_sha256: e.G_BANK_CUSTOMER_MONITORING_AUDIT_SHA256, recovery_audit_sha256: e.G_BANK_RECOVERY_AUDIT_SHA256,
    ha_audit_sha256: e.G_BANK_HA_AUDIT_SHA256, ha_deployment_audit_sha256: e.G_BANK_HA_DEPLOYMENT_AUDIT_SHA256,
  };
  const readiness = {
    schema: 'g-bank-sovereign-readiness/v2', state: 'DIRECT_LIVE_READY', static_configuration_ready: true,
    external_transport_verified: true, prudential_controls_verified: true, operational_controls_verified: true,
    customer_monitoring_verified: true, recovery_controls_verified: true, ha_controls_verified: true, ha_deployment_verified: true,
    direct_live_ready: true, checks: { synthetic_runtime_fixture_verified: true }, evidence_bindings: evidenceBindings,
    recovery_checkpoint_state_root_sha256: H('6'), ha_checkpoint_state_root_sha256: H('6'),
    ha_voter_journal_root_sha256: haState.voter_journal_root_sha256, ha_cluster_authority_root_sha256: haState.cluster_authority_root_sha256,
    ha_fence_valid_until: haState.fence_valid_until, transport_scheme: 'SCT_INST', settlement_system: 'TEST-DIRECT',
    value_movement_permitted_by_readiness: true, note: 'test fixture only',
  };
  const certificate = createTechnicalPromotionCertificate({
    readiness, checkpoint: { schema: 'g-bank-sovereign-state-checkpoint/v2', state_root_sha256: H('6') },
    governance: { policy_sha256: policySha256, authority_set_sha256: authoritySetSha256 }, evidence_bindings: evidenceBindings,
    trusted_signing_key_binding_sha256: promotionSigner.key_binding_sha256,
    trusted_runtime_ha_observer_sha256: runtimeObserver.observer_public_key_binding_sha256,
    promotion_signer_authority_root_sha256: promotionSignerAuthority.authority_root_sha256,
    promotion_signer_authority_epoch: promotionSignerAuthority.authority_epoch,
    promotion_signature_quorum: promotionSignerAuthority.quorum,
    ttl_seconds: 300, now: NOW,
  });
  const readinessPath = path.join(root, 'runtime-readiness.json');
  const promotionPath = path.join(root, 'runtime-promotion.json');
  fs.writeFileSync(readinessPath, JSON.stringify(readiness, null, 2) + '\n', { mode: 0o600 });
  fs.writeFileSync(promotionPath, JSON.stringify(certificate, null, 2) + '\n', { mode: 0o600 });
  e.G_BANK_RUNTIME_READINESS_FILE = readinessPath;
  e.G_BANK_RUNTIME_PROMOTION_CERTIFICATE_FILE = promotionPath;
  e.G_BANK_PROMOTION_CERTIFICATE_SHA256 = certificate.certificate_sha256;
  const promotionSignature = configureSyntheticPromotionSignature({ root, env: e, certificate, promotionSigner, now: NOW });
  return { readiness, certificate, haState, runtimeObserver, promotionSigner, promotionSignerAuthority, promotionSignature };
}

function setup(transport, { promotion = true } = {}) {
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
  ledger.post({ transaction_id: 'GENESIS-FUNDING-1', reference: 'TEST-FUNDING', entries: [
    { account_id: 'G:FUNDING:GENESIS', side: 'DEBIT', amount_minor: 10000, currency: 'EUR' },
    { account_id: 'G:CUSTOMER:001', side: 'CREDIT', amount_minor: 10000, currency: 'EUR' },
  ] });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const operator = { operator_id: 'OPS:PRIMARY:01', role: 'SENIOR_APPROVER', status: 'ACTIVE', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), privateKey };
  const authoritySet = { authority_epoch: 1, operators: [{ operator_id: operator.operator_id, role: operator.role, status: operator.status, public_key_pem: operator.public_key_pem }] };
  const riskPolicy = { currency: 'EUR', max_single_amount_minor: 10000, max_daily_amount_minor: 50000, high_value_threshold_minor: 5000, high_value_quorum: 2, normal_quorum: 1, allowed_schemes: ['SCT_INST'], blocked_beneficiary_hashes: [], policy_epoch: 1 };
  const settlement = new DirectSettlementAdapter({ transport, env: e, clock: () => NOW });
  const core = new GBankSovereignCore({ accounts, ledger, settlement, riskPolicy, authoritySet, stateDir: path.join(root, 'state'), env: e });
  const runtimeObserver = createSyntheticRuntimeObserver();
  const promotionSigner = createSyntheticPromotionSigner('SIGNER:PROMOTION:A');
  const promotionSignerB = createSyntheticPromotionSigner('SIGNER:PROMOTION:B');
  const promotionSignerC = createSyntheticPromotionSigner('SIGNER:PROMOTION:C');
  const promotionSignerAuthority = normalizePromotionSignerAuthority({
    authority_epoch: 1,
    quorum: 2,
    signers: [promotionSigner, promotionSignerB, promotionSignerC].map(s => ({ signer_id: s.signer_id, status: 'ACTIVE', public_key_pem: s.public_key_pem })),
  });
  const runtimePromotion = promotion ? configureRuntimePromotion(root, e, core.riskPolicy.policy_sha256, core.authoritySet.authority_set_sha256, runtimeObserver, promotionSigner, promotionSignerAuthority) : null;
  return { root, e, accounts, ledger, core, riskPolicy, authoritySet, operator, runtimeObserver, promotionSigner, promotionSignerAuthority, runtimePromotion };
}

function bindRuntimeWitness(s, prepared, idempotencyKey) {
  const operation = settlementOperationBinding({ message_sha256: prepared.iso20022.document_sha256, instruction_sha256: prepared.instruction.instruction_sha256, idempotency_key: idempotencyKey, promotion_certificate_sha256: s.runtimePromotion.certificate.certificate_sha256 });
  const witness = issueSyntheticRuntimeHAWitness({ root: s.root, env: s.e, haAudit: s.runtimePromotion.haState.haAudit, haDeploymentAudit: s.runtimePromotion.haState.haDeploymentAudit, runtimeObserver: s.runtimePromotion.runtimeObserver, operation_binding_sha256: operation.operation_binding_sha256, now: NOW });
  return { operation, witness };
}

function schemeEvidence(prepared) {
  return { result: 'PASS', scheme: prepared.instruction.scheme, message_type: prepared.iso20022.message_type, message_sha256: prepared.iso20022.document_sha256, validation_level: 'EXTERNAL_SCHEME_VALIDATED', validator_binding_sha256: H('e'), validation_receipt_sha256: H('f'), observed_at: new Date(NOW).toISOString() };
}

function authoritySignatures(s, prepared, validation, key) {
  const risk = evaluatePaymentPolicy({ prepared, policy: s.riskPolicy, receiptRows: s.core.receipts.readAll(), now: NOW });
  const payload = approvalPayload({ prepared, schemeValidationEvidence: validation, riskDecision: risk, idempotencyKey: key, authorityEpoch: s.authoritySet.authority_epoch });
  return [{ operator_id: s.operator.operator_id, payload_sha256: payload.payload_sha256, signed_at: new Date(NOW).toISOString(), signature_base64: crypto.sign(null, Buffer.from(payload.payload_sha256, 'utf8'), s.operator.privateKey).toString('base64') }];
}

(async () => {
  let submitCount = 0;
  const settledTransport = {
    async preflight() { return { environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST', settlement_system: 'TEST-DIRECT', external_receipt_sha256: H('5') }; },
    async submit(request) {
      submitCount += 1;
      assert.match(request.settlement_operation_binding_sha256, /^[0-9a-f]{64}$/);
      assert.equal(request.settlement_operation_binding_sha256, request.ha_runtime_challenge_operation_binding_sha256);
      assert.match(request.runtime_promotion_gate_sha256, /^[0-9a-f]{64}$/);
      assert.match(request.promotion_certificate_sha256, /^[0-9a-f]{64}$/);
      assert.match(request.trusted_runtime_ha_observer_sha256, /^[0-9a-f]{64}$/);
      assert.equal(request.recovery_audit_sha256, H('5'));
      assert.equal(request.customer_monitoring_audit_sha256, H('4'));
      assert.match(request.ha_audit_sha256, /^[0-9a-f]{64}$/);
      assert.match(request.ha_deployment_audit_sha256, /^[0-9a-f]{64}$/);
      assert.equal(request.ha_voter_journal_root_sha256, H('7'));
      assert.equal(request.ha_cluster_authority_root_sha256, H('8'));
      assert.match(request.ha_runtime_attestation_audit_sha256, /^[0-9a-f]{64}$/);
      assert.match(request.ha_runtime_observation_sha256, /^[0-9a-f]{64}$/);
      return { submission_id: 'SUB-001', status: 'SUBMITTED', external_receipt_sha256: H('6'), provider_request_id: 'REQ-001' };
    },
    async readback() { return { status: 'SETTLED', settlement_reference: 'SETTLE-001', external_receipt_sha256: H('7') }; },
  };
  const s = setup(settledTransport);
  const prepared = s.core.prepare({ rawInstruction: instruction(), complianceBundle: evidence(), now: NOW });
  const key = crypto.randomUUID();
  const validation = schemeEvidence(prepared);
  const approval = createSovereignApproval({ prepared, schemeValidationEvidence: validation, idempotencyKey: key, now: NOW }, s.e);
  const signatures = authoritySignatures(s, prepared, validation, key);
  const runtime = bindRuntimeWitness(s, prepared, key);
  const result = await s.core.execute({ prepared, schemeValidationEvidence: validation, approvalToken: approval, authoritySignatures: signatures, idempotencyKey: key, now: NOW });
  assert.equal(result.state, 'SETTLED');
  assert.equal(result.value_moved, true);
  assert.equal(result.verified_value_flow, true);
  assert.equal(runtime.witness.challenge.operation_binding_sha256, runtime.operation.operation_binding_sha256);
  assert.equal(s.runtimePromotion.certificate.trusted_runtime_ha_observer_sha256, s.runtimeObserver.observer_public_key_binding_sha256);
  assert.equal(s.runtimePromotion.certificate.trusted_signing_key_binding_sha256, s.promotionSigner.key_binding_sha256);
  assert.equal(s.runtimePromotion.certificate.promotion_signer_authority_root_sha256, s.promotionSignerAuthority.authority_root_sha256);
  assert.equal(s.runtimePromotion.certificate.promotion_signature_quorum, 2);
  assert.equal(s.ledger.balance('G:CUSTOMER:001', 'EUR'), 9000);
  assert.equal(s.ledger.balance('G:SUSPENSE:OUTBOUND', 'EUR'), 0);
  assert.equal(s.ledger.balance('G:SETTLEMENT:OUTBOUND', 'EUR'), 1000);
  assert.equal(s.ledger.verify().verified, true);
  assert.equal(s.core.receipts.verify().valid, true);
  const replay = await s.core.execute({ prepared, schemeValidationEvidence: null, approvalToken: null, authoritySignatures: null, idempotencyKey: key, now: NOW + 86400000 });
  assert.equal(replay.result_sha256, result.result_sha256);
  assert.equal(submitCount, 1);

  assert.throws(() => createSovereignApproval({ prepared, schemeValidationEvidence: validation, idempotencyKey: '', now: NOW }, s.e), /idempotency_key_required/);
  const wrongKey = crypto.randomUUID();
  assert.throws(() => verifySovereignApproval(approval, { prepared, schemeValidationEvidence: validation, idempotencyKey: wrongKey, now: NOW }, s.e), /approval_idempotency_mismatch/);

  let blockedSubmitCount = 0;
  const blockedTransport = { async preflight() { return { environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST', settlement_system: 'TEST-DIRECT', external_receipt_sha256: H('5') }; }, async submit() { blockedSubmitCount += 1; return { submission_id: 'MUST-NOT-HAPPEN', external_receipt_sha256: H('6') }; }, async readback() { return { status: 'UNKNOWN', external_receipt_sha256: H('7') }; } };
  const blocked = setup(blockedTransport, { promotion: false });
  const blockedPrepared = blocked.core.prepare({ rawInstruction: instruction('PAY0000000000008'), complianceBundle: evidence(), now: NOW });
  const blockedKey = crypto.randomUUID();
  const blockedValidation = schemeEvidence(blockedPrepared);
  const blockedApproval = createSovereignApproval({ prepared: blockedPrepared, schemeValidationEvidence: blockedValidation, idempotencyKey: blockedKey, now: NOW }, blocked.e);
  const blockedSignatures = authoritySignatures(blocked, blockedPrepared, blockedValidation, blockedKey);
  await assert.rejects(blocked.core.execute({ prepared: blockedPrepared, schemeValidationEvidence: blockedValidation, approvalToken: blockedApproval, authoritySignatures: blockedSignatures, idempotencyKey: blockedKey, now: NOW }), /runtime_readiness_file_required/);
  assert.equal(blockedSubmitCount, 0);

  const noSig = setup(settledTransport);
  const noSigPrepared = noSig.core.prepare({ rawInstruction: instruction('PAY0000000000009'), complianceBundle: evidence(), now: NOW });
  const noSigKey = crypto.randomUUID();
  const noSigValidation = schemeEvidence(noSigPrepared);
  const noSigApproval = createSovereignApproval({ prepared: noSigPrepared, schemeValidationEvidence: noSigValidation, idempotencyKey: noSigKey, now: NOW }, noSig.e);
  await assert.rejects(noSig.core.execute({ prepared: noSigPrepared, schemeValidationEvidence: noSigValidation, approvalToken: noSigApproval, authoritySignatures: [], idempotencyKey: noSigKey, now: NOW }), /approval_quorum_not_met/);

  let ambiguousSubmits = 0;
  const ambiguousTransport = { async preflight() { return { environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST', settlement_system: 'TEST-DIRECT', external_receipt_sha256: H('8') }; }, async submit() { ambiguousSubmits += 1; throw new Error('transport_connection_dropped_after_submit'); }, async readback() { throw new Error('should_not_be_called_without_submission_id'); } };
  const a = setup(ambiguousTransport);
  const p2 = a.core.prepare({ rawInstruction: instruction('PAY0000000000002'), complianceBundle: evidence(), now: NOW });
  const k2 = crypto.randomUUID();
  const v2 = schemeEvidence(p2);
  const ap2 = createSovereignApproval({ prepared: p2, schemeValidationEvidence: v2, idempotencyKey: k2, now: NOW }, a.e);
  const sig2 = authoritySignatures(a, p2, v2, k2);
  bindRuntimeWitness(a, p2, k2);
  await assert.rejects(a.core.execute({ prepared: p2, schemeValidationEvidence: v2, approvalToken: ap2, authoritySignatures: sig2, idempotencyKey: k2, now: NOW }), /transport_connection_dropped_after_submit/);
  assert.equal(a.core.executions.read(k2).state, 'UNKNOWN');
  await assert.rejects(a.core.execute({ prepared: p2, schemeValidationEvidence: v2, approvalToken: ap2, authoritySignatures: sig2, idempotencyKey: k2, now: NOW }), /execution_exists_unknown_use_reconcile/);
  assert.equal(ambiguousSubmits, 1);

  console.log('G-BANK sovereign v2 quorum-bound externally-signed promotion no-network safety tests: PASS');
})().catch(err => { console.error(err); process.exit(1); });
