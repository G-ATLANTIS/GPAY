'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { createTechnicalPromotionCertificate } = require('../g-bank-sovereign-v2/promotion-certificate');
const { verifyRuntimePromotionGate } = require('../g-bank-sovereign-v2/runtime-promotion-gate');
const { runtimeHAObservationPayload, signHARuntimeObservation } = require('../g-bank-sovereign-v2/ha-runtime-attestation');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T09:30:00.000Z');
const FENCE = new Date(NOW + 120000).toISOString();

function hashed(schema, hashField, extra = {}) {
  const body = { schema, state: 'PASS', ...extra };
  return Object.freeze({ ...body, [hashField]: sha256(canonicalJson(body)) });
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-runtime-gate-v2-'));
  const haAudit = hashed('g-bank-ha-readiness-audit/v2', 'audit_sha256', {
    cluster_sha256: H('1'), cluster_epoch: 1, cluster_authority_root_sha256: H('2'), cluster_transition_count: 0,
    cluster_transition_head_sha256: null, active_voter_count: 3, quorum: 2, latest_term: 8, leader_node_id: 'NODE:A',
    fence_record_sha256: H('3'), fence_valid_until: FENCE, latest_commit_index: 42, latest_commit_sha256: H('4'),
    replicated_state_root_sha256: H('b'), checkpoint_state_root_sha256: H('b'), voter_journal_store_count: 3,
    voter_journal_heads: { 'NODE:A': H('a'), 'NODE:B': H('b'), 'NODE:C': null }, voter_journal_root_sha256: H('c'),
    durable_fence_signer_count: 2, durable_commit_signer_count: 2, reasons: [], audited_at: new Date(NOW).toISOString(),
    grants_external_rights: false, permits_value_movement_by_itself: false, distributed_network_verified: false,
  });
  const haDeploymentAudit = hashed('g-bank-ha-deployment-audit/v2', 'audit_sha256', {
    cluster_sha256: H('1'), cluster_epoch: 1, active_voter_count: 3, observed_active_voter_count: 3,
    observer_id: 'OBSERVER:DEPLOYMENT', observer_public_key_binding_sha256: H('d'), observation_sha256: H('e'),
    observed_at: new Date(NOW).toISOString(), audited_at: new Date(NOW).toISOString(), distributed_network_verified: true,
    all_active_voters_healthy: true, unique_machine_identities_verified: true, unique_endpoints_verified: true,
    unique_failure_domains_verified: true, grants_external_rights: false, permits_value_movement_by_itself: false,
  });
  const evidence_bindings = {
    legal_authorization_evidence_sha256: H('1'), scheme_participation_evidence_sha256: H('2'),
    settlement_access_evidence_sha256: H('3'), production_identity_evidence_sha256: H('4'),
    transport_preflight_receipt_sha256: H('5'), prudential_audit_sha256: H('6'),
    operational_resilience_sha256: H('7'), treasury_assessment_sha256: H('8'),
    customer_monitoring_audit_sha256: H('9'), recovery_audit_sha256: H('a'),
    ha_audit_sha256: haAudit.audit_sha256, ha_deployment_audit_sha256: haDeploymentAudit.audit_sha256,
  };
  const readiness = {
    schema: 'g-bank-sovereign-readiness/v2', state: 'DIRECT_LIVE_READY',
    static_configuration_ready: true, external_transport_verified: true, prudential_controls_verified: true,
    operational_controls_verified: true, customer_monitoring_verified: true, recovery_controls_verified: true,
    ha_controls_verified: true, ha_deployment_verified: true, direct_live_ready: true,
    checks: { live_flag: true, recovery_audit_pass: true, customer_monitoring_pass: true, ha_audit_pass: true, ha_deployment_pass: true },
    evidence_bindings,
    recovery_checkpoint_state_root_sha256: H('b'), ha_checkpoint_state_root_sha256: H('b'),
    ha_voter_journal_root_sha256: H('c'), ha_cluster_authority_root_sha256: H('2'), ha_fence_valid_until: FENCE,
    transport_scheme: 'SCT_INST', settlement_system: 'TEST-DIRECT', value_movement_permitted_by_readiness: true,
    note: 'runtime gate test fixture',
  };
  const certificate = createTechnicalPromotionCertificate({
    readiness,
    checkpoint: { schema: 'g-bank-sovereign-state-checkpoint/v2', state_root_sha256: H('b') },
    governance: { policy_sha256: H('c'), authority_set_sha256: H('d') },
    evidence_bindings,
    trusted_signing_key_binding_sha256: H('e'), ttl_seconds: 300, now: NOW,
  });

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const runtimeObserver = { observer_id: 'OBSERVER:RUNTIME:PRIMARY', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString() };
  const runtimePayload = runtimeHAObservationPayload({
    haAudit, haDeploymentAudit, observer: runtimeObserver, observed_at: new Date(NOW).toISOString(), nonce_sha256: H('f'),
  });
  const runtimeObservation = signHARuntimeObservation({ payload: runtimePayload, private_key: privateKey });

  const readinessFile = path.join(root, 'readiness.json');
  const promotionFile = path.join(root, 'promotion.json');
  const runtimeHAFile = path.join(root, 'runtime-ha.json');
  const runtimeHAObserverFile = path.join(root, 'runtime-ha-observer.json');
  fs.writeFileSync(readinessFile, JSON.stringify(readiness, null, 2) + '\n', { mode: 0o600 });
  fs.writeFileSync(promotionFile, JSON.stringify(certificate, null, 2) + '\n', { mode: 0o600 });
  fs.writeFileSync(runtimeHAFile, JSON.stringify(runtimeObservation, null, 2) + '\n', { mode: 0o600 });
  fs.writeFileSync(runtimeHAObserverFile, JSON.stringify(runtimeObserver, null, 2) + '\n', { mode: 0o600 });
  const env = {
    G_BANK_RUNTIME_READINESS_FILE: readinessFile,
    G_BANK_RUNTIME_PROMOTION_CERTIFICATE_FILE: promotionFile,
    G_BANK_RUNTIME_HA_ATTESTATION_FILE: runtimeHAFile,
    G_BANK_RUNTIME_HA_OBSERVER_FILE: runtimeHAObserverFile,
    G_BANK_PROMOTION_CERTIFICATE_SHA256: certificate.certificate_sha256,
    G_BANK_ACTIVE_POLICY_SHA256: H('c'), G_BANK_ACTIVE_AUTHORITY_SET_SHA256: H('d'),
    G_BANK_LEGAL_AUTHORIZATION_EVIDENCE_SHA256: evidence_bindings.legal_authorization_evidence_sha256,
    G_BANK_SCHEME_PARTICIPATION_EVIDENCE_SHA256: evidence_bindings.scheme_participation_evidence_sha256,
    G_BANK_SETTLEMENT_ACCESS_EVIDENCE_SHA256: evidence_bindings.settlement_access_evidence_sha256,
    G_BANK_PRODUCTION_IDENTITY_EVIDENCE_SHA256: evidence_bindings.production_identity_evidence_sha256,
    G_BANK_PRUDENTIAL_AUDIT_SHA256: evidence_bindings.prudential_audit_sha256,
    G_BANK_OPERATIONAL_RESILIENCE_SHA256: evidence_bindings.operational_resilience_sha256,
    G_BANK_TREASURY_ASSESSMENT_SHA256: evidence_bindings.treasury_assessment_sha256,
    G_BANK_CUSTOMER_MONITORING_AUDIT_SHA256: evidence_bindings.customer_monitoring_audit_sha256,
    G_BANK_RECOVERY_AUDIT_SHA256: evidence_bindings.recovery_audit_sha256,
    G_BANK_HA_AUDIT_SHA256: evidence_bindings.ha_audit_sha256,
    G_BANK_HA_DEPLOYMENT_AUDIT_SHA256: evidence_bindings.ha_deployment_audit_sha256,
  };
  return { root, readiness, certificate, runtimeObservation, readinessFile, promotionFile, runtimeHAFile, runtimeHAObserverFile, env };
}

(() => {
  const f = fixture();
  const gate = verifyRuntimePromotionGate({ env: f.env, now: NOW + 1000 });
  assert.equal(gate.state, 'PASS');
  assert.equal(gate.runtime_submit_gate_satisfied, true);
  assert.equal(gate.grants_external_rights, false);
  assert.equal(gate.permits_value_movement_by_itself, false);
  assert.equal(gate.recovery_audit_sha256, H('a'));
  assert.equal(gate.ha_voter_journal_root_sha256, H('c'));
  assert.equal(gate.ha_cluster_authority_root_sha256, H('2'));
  assert.match(gate.ha_runtime_attestation_audit_sha256, /^[0-9a-f]{64}$/);
  assert.equal(gate.ha_runtime_observation_sha256, f.runtimeObservation.observation_sha256);
  assert.equal(gate.ha_fence_valid_until, FENCE);
  assert.equal(gate.policy_sha256, H('c'));
  assert.equal(gate.authority_set_sha256, H('d'));
  assert.equal(f.certificate.expires_at, FENCE, 'certificate lifetime must be capped to leader fence');
  assert.match(gate.gate_sha256, /^[0-9a-f]{64}$/);
})();

for (const [field, value, pattern] of [
  ['G_BANK_ACTIVE_POLICY_SHA256', H('0'), /runtime_promotion_policy_binding_mismatch/],
  ['G_BANK_ACTIVE_AUTHORITY_SET_SHA256', H('0'), /runtime_promotion_authority_binding_mismatch/],
  ['G_BANK_RECOVERY_AUDIT_SHA256', H('0'), /runtime_promotion_evidence_binding_mismatch:recovery_audit_sha256/],
  ['G_BANK_HA_AUDIT_SHA256', H('1'), /runtime_promotion_evidence_binding_mismatch:ha_audit_sha256/],
  ['G_BANK_HA_DEPLOYMENT_AUDIT_SHA256', H('1'), /runtime_promotion_evidence_binding_mismatch:ha_deployment_audit_sha256/],
  ['G_BANK_PROMOTION_CERTIFICATE_SHA256', H('0'), /runtime_promotion_certificate_binding_mismatch/],
]) {
  const f = fixture();
  assert.throws(() => verifyRuntimePromotionGate({ env: { ...f.env, [field]: value }, now: NOW + 1000 }), pattern);
}

(() => {
  const f = fixture();
  fs.writeFileSync(f.promotionFile, JSON.stringify({ ...f.certificate, state_root_sha256: H('0') }, null, 2) + '\n');
  assert.throws(() => verifyRuntimePromotionGate({ env: f.env, now: NOW + 1000 }), /promotion_certificate_hash_mismatch/);
})();

(() => {
  const f = fixture();
  fs.writeFileSync(f.runtimeHAFile, JSON.stringify({ ...f.runtimeObservation, cluster_authority_root_sha256: H('9') }, null, 2) + '\n');
  assert.throws(() => verifyRuntimePromotionGate({ env: f.env, now: NOW + 1000 }), /ha_runtime_observation_hash_mismatch/);
})();

(() => {
  const f = fixture();
  fs.writeFileSync(f.runtimeHAFile, JSON.stringify({ ...f.runtimeObservation, signature_base64: Buffer.from('forged').toString('base64') }, null, 2) + '\n');
  assert.throws(() => verifyRuntimePromotionGate({ env: f.env, now: NOW + 1000 }), /ha_runtime_observer_signature_invalid/);
})();

(() => {
  const f = fixture();
  assert.throws(() => verifyRuntimePromotionGate({ env: f.env, now: NOW + 16000 }), /ha_runtime_observation_stale_or_future/);
})();

(() => {
  const f = fixture();
  assert.throws(() => verifyRuntimePromotionGate({ env: { ...f.env, G_BANK_RUNTIME_HA_ATTESTATION_FILE: '' }, now: NOW + 1000 }), /runtime_ha_attestation_file_required/);
})();

(() => {
  const f = fixture();
  const link = path.join(f.root, 'readiness-link.json');
  fs.symlinkSync(f.readinessFile, link);
  assert.throws(() => verifyRuntimePromotionGate({ env: { ...f.env, G_BANK_RUNTIME_READINESS_FILE: link }, now: NOW + 1000 }), /runtime_readiness_file_invalid/);
})();

console.log('G-BANK sovereign v2 runtime promotion gate tests: PASS');
