'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DirectSettlementAdapter } = require('../g-bank-sovereign-v2/direct-settlement');
const { createTechnicalPromotionCertificate } = require('../g-bank-sovereign-v2/promotion-certificate');
const { normalizePromotionSignerAuthority } = require('../g-bank-sovereign-v2/promotion-signer-authority');
const { settlementOperationBinding } = require('../g-bank-sovereign-v2/settlement-operation-binding');
const { HARuntimeChallengeStore } = require('../g-bank-sovereign-v2/ha-runtime-challenge-store');
const { createSyntheticRuntimeObserver, configureSyntheticHAState, issueSyntheticRuntimeHAWitness } = require('./g-bank-sovereign-v2-runtime-ha-fixture');
const { createSyntheticPromotionSigner, configureSyntheticPromotionSignature, configureSyntheticPromotionQuorum } = require('./g-bank-sovereign-v2-promotion-signing-fixture');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T12:00:00.000Z');

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-operation-binding-v2-'));
  const runtimeObserver = createSyntheticRuntimeObserver();
  const promotionSigner = createSyntheticPromotionSigner('SIGNER:PROMOTION:A');
  const promotionSignerB = createSyntheticPromotionSigner('SIGNER:PROMOTION:B');
  const promotionSignerC = createSyntheticPromotionSigner('SIGNER:PROMOTION:C');
  const promotionSigners = [promotionSigner, promotionSignerB, promotionSignerC];
  const promotionSignerAuthority = normalizePromotionSignerAuthority({
    authority_epoch: 1,
    quorum: 2,
    signers: promotionSigners.map(s => ({ signer_id: s.signer_id, status: 'ACTIVE', public_key_pem: s.public_key_pem })),
  });
  const env = {
    G_BANK_ENABLE_LIVE: 'true', G_BANK_EXTERNAL_ACTIONS_ENABLED: 'true', G_BANK_DIRECT_SETTLEMENT_ENABLED: 'true',
    G_BANK_SIMULATED_LIVE_SUCCESS: 'false', G_BANK_SETTLEMENT_AUTHORIZATION_SHA256: H('a'),
    G_BANK_ACTIVE_POLICY_SHA256: H('b'), G_BANK_ACTIVE_AUTHORITY_SET_SHA256: H('c'),
    G_BANK_LEGAL_AUTHORIZATION_EVIDENCE_SHA256: H('1'), G_BANK_SCHEME_PARTICIPATION_EVIDENCE_SHA256: H('2'),
    G_BANK_SETTLEMENT_ACCESS_EVIDENCE_SHA256: H('3'), G_BANK_PRODUCTION_IDENTITY_EVIDENCE_SHA256: H('4'),
    G_BANK_PRUDENTIAL_AUDIT_SHA256: H('5'), G_BANK_OPERATIONAL_RESILIENCE_SHA256: H('6'),
    G_BANK_TREASURY_ASSESSMENT_SHA256: H('7'), G_BANK_CUSTOMER_MONITORING_AUDIT_SHA256: H('8'), G_BANK_RECOVERY_AUDIT_SHA256: H('9'),
  };
  const fence = new Date(NOW + 120000).toISOString();
  const haState = configureSyntheticHAState({ env, state_root_sha256: H('d'), cluster_authority_root_sha256: H('e'), voter_journal_root_sha256: H('f'), fence_valid_until: fence, now: NOW });
  const evidence_bindings = {
    legal_authorization_evidence_sha256: env.G_BANK_LEGAL_AUTHORIZATION_EVIDENCE_SHA256, scheme_participation_evidence_sha256: env.G_BANK_SCHEME_PARTICIPATION_EVIDENCE_SHA256,
    settlement_access_evidence_sha256: env.G_BANK_SETTLEMENT_ACCESS_EVIDENCE_SHA256, production_identity_evidence_sha256: env.G_BANK_PRODUCTION_IDENTITY_EVIDENCE_SHA256,
    transport_preflight_receipt_sha256: H('a'), prudential_audit_sha256: env.G_BANK_PRUDENTIAL_AUDIT_SHA256,
    operational_resilience_sha256: env.G_BANK_OPERATIONAL_RESILIENCE_SHA256, treasury_assessment_sha256: env.G_BANK_TREASURY_ASSESSMENT_SHA256,
    customer_monitoring_audit_sha256: env.G_BANK_CUSTOMER_MONITORING_AUDIT_SHA256, recovery_audit_sha256: env.G_BANK_RECOVERY_AUDIT_SHA256,
    ha_audit_sha256: env.G_BANK_HA_AUDIT_SHA256, ha_deployment_audit_sha256: env.G_BANK_HA_DEPLOYMENT_AUDIT_SHA256,
  };
  const readiness = {
    schema: 'g-bank-sovereign-readiness/v2', state: 'DIRECT_LIVE_READY', static_configuration_ready: true,
    external_transport_verified: true, prudential_controls_verified: true, operational_controls_verified: true,
    customer_monitoring_verified: true, recovery_controls_verified: true, ha_controls_verified: true, ha_deployment_verified: true,
    direct_live_ready: true, checks: { transaction_bound_fixture: true }, evidence_bindings,
    recovery_checkpoint_state_root_sha256: H('d'), ha_checkpoint_state_root_sha256: H('d'), ha_voter_journal_root_sha256: H('f'),
    ha_cluster_authority_root_sha256: H('e'), ha_fence_valid_until: fence, transport_scheme: 'SCT_INST', settlement_system: 'TEST', value_movement_permitted_by_readiness: true,
  };
  const certificate = createTechnicalPromotionCertificate({
    readiness, checkpoint: { schema: 'g-bank-sovereign-state-checkpoint/v2', state_root_sha256: H('d') },
    governance: { policy_sha256: H('b'), authority_set_sha256: H('c') }, evidence_bindings,
    trusted_signing_key_binding_sha256: promotionSigner.key_binding_sha256,
    trusted_runtime_ha_observer_sha256: runtimeObserver.observer_public_key_binding_sha256,
    promotion_signer_authority_root_sha256: promotionSignerAuthority.authority_root_sha256,
    promotion_signer_authority_epoch: promotionSignerAuthority.authority_epoch,
    promotion_signature_quorum: promotionSignerAuthority.quorum,
    ttl_seconds: 120, now: NOW,
  });
  const readinessPath = path.join(root, 'readiness.json');
  const promotionPath = path.join(root, 'promotion.json');
  fs.writeFileSync(readinessPath, JSON.stringify(readiness) + '\n', { mode: 0o600 });
  fs.writeFileSync(promotionPath, JSON.stringify(certificate) + '\n', { mode: 0o600 });
  env.G_BANK_RUNTIME_READINESS_FILE = readinessPath;
  env.G_BANK_RUNTIME_PROMOTION_CERTIFICATE_FILE = promotionPath;
  env.G_BANK_PROMOTION_CERTIFICATE_SHA256 = certificate.certificate_sha256;
  const promotionSignature = configureSyntheticPromotionSignature({ root, env, certificate, promotionSigner, now: NOW });
  const promotionQuorum = configureSyntheticPromotionQuorum({
    root, env, certificate, authority: promotionSignerAuthority, promotionSigners,
    request: promotionSignature.request, now: NOW,
  });
  return { root, env, haState, certificate, runtimeObserver, promotionSigner, promotionSigners, promotionSignerAuthority, promotionSignature, promotionQuorum };
}

(async () => {
  const f = fixture();
  const paymentA = { message: { message_type: 'pacs.008.001.08', document: '<A/>', document_sha256: H('1') }, instruction: { instruction_sha256: H('2'), scheme: 'SCT_INST' }, idempotencyKey: 'payment-A' };
  const paymentB = { ...paymentA, instruction: { ...paymentA.instruction, instruction_sha256: H('3') }, idempotencyKey: 'payment-B' };
  const operationA = settlementOperationBinding({ message_sha256: paymentA.message.document_sha256, instruction_sha256: paymentA.instruction.instruction_sha256, idempotency_key: paymentA.idempotencyKey, promotion_certificate_sha256: f.certificate.certificate_sha256 });
  const witness = issueSyntheticRuntimeHAWitness({ root: f.root, env: f.env, haAudit: f.haState.haAudit, haDeploymentAudit: f.haState.haDeploymentAudit, runtimeObserver: f.runtimeObserver, operation_binding_sha256: operationA.operation_binding_sha256, now: NOW });
  let submits = 0;
  const transport = {
    async preflight() { return { environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST', settlement_system: 'TEST', external_receipt_sha256: H('a'), observed_at: new Date(NOW).toISOString() }; },
    async submit(request) {
      submits += 1;
      assert.equal(request.settlement_operation_binding_sha256, operationA.operation_binding_sha256);
      assert.equal(request.trusted_runtime_ha_observer_sha256, f.runtimeObserver.observer_public_key_binding_sha256);
      return { submission_id: 'SUB-A', status: 'SUBMITTED', external_receipt_sha256: H('b') };
    },
    async readback() { return { status: 'ACCEPTED', external_receipt_sha256: H('c') }; },
  };
  const adapter = new DirectSettlementAdapter({ transport, env: f.env, clock: () => NOW + 2000 });
  await adapter.preflight();
  await assert.rejects(adapter.submit(paymentB), /ha_runtime_expected_mismatch:operation_binding_sha256|ha_runtime_challenge_operation_binding_mismatch/);
  assert.equal(submits, 0);
  assert.equal(new HARuntimeChallengeStore(witness.challenge_store_path).verify().consumed_count, 0);
  const receipt = await adapter.submit(paymentA);
  assert.equal(submits, 1);
  assert.equal(receipt.settlement_operation_binding_sha256, operationA.operation_binding_sha256);
  assert.equal(receipt.trusted_runtime_ha_observer_sha256, f.runtimeObserver.observer_public_key_binding_sha256);
  assert.equal(f.certificate.promotion_signer_authority_root_sha256, f.promotionSignerAuthority.authority_root_sha256);
  assert.equal(f.certificate.promotion_signature_quorum, 2);
  assert.equal(f.promotionQuorum.bundle.signatures.length, 2);
  assert.equal(new HARuntimeChallengeStore(witness.challenge_store_path).verify().consumed_count, 1);
  console.log('G-BANK sovereign v2 promotion signer quorum settlement boundary tests: PASS');
})().catch(err => { console.error(err); process.exit(1); });
