'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createTechnicalPromotionCertificate, verifyTechnicalPromotionCertificate } = require('../g-bank-sovereign-v2/promotion-certificate');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T22:30:00.000Z');
const FENCE = new Date(NOW + 180000).toISOString();
const TRUSTED_OBSERVER = H('6');
const PROMOTION_AUTH_ROOT = H('4');
const PROMOTION_AUTH_EPOCH = 3;
const PROMOTION_QUORUM = 2;

const evidence_bindings = {
  legal_authorization_evidence_sha256: H('d'), scheme_participation_evidence_sha256: H('e'), settlement_access_evidence_sha256: H('f'),
  production_identity_evidence_sha256: H('1'), transport_preflight_receipt_sha256: H('2'), prudential_audit_sha256: H('3'),
  operational_resilience_sha256: H('4'), treasury_assessment_sha256: H('5'), customer_monitoring_audit_sha256: H('6'),
  recovery_audit_sha256: H('8'), ha_audit_sha256: H('9'), ha_deployment_audit_sha256: H('0'),
};

function readiness(overrides = {}) {
  return {
    schema: 'g-bank-sovereign-readiness/v2', state: 'DIRECT_LIVE_READY', static_configuration_ready: true,
    external_transport_verified: true, prudential_controls_verified: true, operational_controls_verified: true,
    customer_monitoring_verified: true, recovery_controls_verified: true, ha_controls_verified: true,
    ha_deployment_verified: true, direct_live_ready: true, value_movement_permitted_by_readiness: true,
    checks: { synthetic_test_snapshot: true }, evidence_bindings: { ...evidence_bindings },
    recovery_checkpoint_state_root_sha256: H('a'), ha_checkpoint_state_root_sha256: H('a'),
    ha_voter_journal_root_sha256: H('1'), ha_cluster_authority_root_sha256: H('2'),
    ha_fence_valid_until: FENCE, ...overrides,
  };
}

const checkpoint = { schema: 'g-bank-sovereign-state-checkpoint/v2', state_root_sha256: H('a') };
const governance = { policy_sha256: H('b'), authority_set_sha256: H('c') };
const ready = readiness();
const baseArgs = {
  readiness: ready,
  checkpoint,
  governance,
  evidence_bindings,
  trusted_signing_key_binding_sha256: H('7'),
  trusted_runtime_ha_observer_sha256: TRUSTED_OBSERVER,
  promotion_signer_authority_root_sha256: PROMOTION_AUTH_ROOT,
  promotion_signer_authority_epoch: PROMOTION_AUTH_EPOCH,
  promotion_signature_quorum: PROMOTION_QUORUM,
};
const cert = createTechnicalPromotionCertificate({ ...baseArgs, ttl_seconds: 120, now: NOW });

assert.equal(cert.state, 'TECHNICAL_GATES_SATISFIED');
assert.equal(cert.grants_external_rights, false);
assert.equal(cert.permits_value_movement_by_itself, false);
assert.equal(cert.requires_runtime_reverification, true);
assert.equal(cert.trusted_runtime_ha_observer_sha256, TRUSTED_OBSERVER);
assert.equal(cert.promotion_signer_authority_root_sha256, PROMOTION_AUTH_ROOT);
assert.equal(cert.promotion_signer_authority_epoch, PROMOTION_AUTH_EPOCH);
assert.equal(cert.promotion_signature_quorum, PROMOTION_QUORUM);
assert.equal(cert.evidence_bindings.recovery_audit_sha256, H('8'));
assert.equal(cert.evidence_bindings.ha_audit_sha256, H('9'));
assert.equal(cert.evidence_bindings.ha_deployment_audit_sha256, H('0'));
assert.equal(cert.ha_voter_journal_root_sha256, H('1'));
assert.equal(cert.ha_cluster_authority_root_sha256, H('2'));
assert.equal(cert.ha_fence_valid_until, FENCE);
assert.equal(cert.expires_at, new Date(NOW + 120000).toISOString());
assert.match(cert.certificate_sha256, /^[0-9a-f]{64}$/);
assert.equal(verifyTechnicalPromotionCertificate(cert, { readiness: ready, now: NOW + 1000 }), true);

const fenceReady = readiness({ ha_fence_valid_until: new Date(NOW + 90000).toISOString() });
const fenceCapped = createTechnicalPromotionCertificate({ ...baseArgs, readiness: fenceReady, ttl_seconds: 300, now: NOW });
assert.equal(fenceCapped.expires_at, new Date(NOW + 90000).toISOString());
assert.throws(() => verifyTechnicalPromotionCertificate(fenceCapped, { readiness: fenceReady, now: NOW + 90000 }), /readiness_ha_fence_expired_or_invalid|expired_or_invalid/);

assert.throws(() => createTechnicalPromotionCertificate({ ...baseArgs, readiness: readiness({ ha_fence_valid_until: new Date(NOW + 29000).toISOString() }), ttl_seconds: 120, now: NOW }), /promotion_ha_fence_too_close_to_expiry/);
assert.throws(() => createTechnicalPromotionCertificate({ ...baseArgs, readiness: readiness({ ha_cluster_authority_root_sha256: null }), now: NOW }), /readiness_ha_cluster_authority_root_sha256_invalid/);
assert.throws(() => createTechnicalPromotionCertificate({ ...baseArgs, readiness: readiness({ ha_voter_journal_root_sha256: null }), now: NOW }), /readiness_ha_voter_journal_root_sha256_invalid/);
assert.throws(() => createTechnicalPromotionCertificate({ ...baseArgs, trusted_runtime_ha_observer_sha256: null, now: NOW }), /trusted_runtime_ha_observer_sha256_invalid/);
assert.throws(() => createTechnicalPromotionCertificate({ ...baseArgs, promotion_signer_authority_root_sha256: null, now: NOW }), /promotion_signer_authority_root_sha256_invalid/);
assert.throws(() => createTechnicalPromotionCertificate({ ...baseArgs, promotion_signer_authority_epoch: 0, now: NOW }), /promotion_signer_authority_epoch_invalid/);
assert.throws(() => createTechnicalPromotionCertificate({ ...baseArgs, promotion_signature_quorum: 1, now: NOW }), /promotion_signature_quorum_invalid/);
assert.throws(() => verifyTechnicalPromotionCertificate({ ...cert, state_root_sha256: H('f') }, { readiness: ready, now: NOW + 1000 }), /hash_mismatch/);
assert.throws(() => verifyTechnicalPromotionCertificate(cert, { readiness: ready, now: NOW + 121000 }), /expired_or_invalid/);

for (const field of ['customer_monitoring_verified', 'recovery_controls_verified', 'ha_controls_verified', 'ha_deployment_verified']) {
  assert.throws(() => createTechnicalPromotionCertificate({ ...baseArgs, readiness: readiness({ [field]: false }), now: NOW }), /direct_live_readiness_not_satisfied/);
}

assert.throws(() => createTechnicalPromotionCertificate({ ...baseArgs, checkpoint: { ...checkpoint, state_root_sha256: H('f') }, now: NOW }), /promotion_recovery_checkpoint_state_root_mismatch/);
assert.throws(() => createTechnicalPromotionCertificate({ ...baseArgs, readiness: readiness({ ha_checkpoint_state_root_sha256: H('f') }), now: NOW }), /readiness_ha_recovery_checkpoint_mismatch/);
assert.throws(() => createTechnicalPromotionCertificate({ ...baseArgs, evidence_bindings: { ...evidence_bindings, ha_deployment_audit_sha256: H('1') }, now: NOW }), /promotion_readiness_evidence_binding_mismatch:ha_deployment_audit_sha256/);
assert.throws(() => verifyTechnicalPromotionCertificate(cert, { readiness: readiness({ ha_cluster_authority_root_sha256: H('3') }), now: NOW + 1000 }), /promotion_ha_cluster_authority_root_mismatch|readiness_mismatch/);
assert.throws(() => verifyTechnicalPromotionCertificate(cert, { readiness: readiness({ ha_voter_journal_root_sha256: H('3') }), now: NOW + 1000 }), /promotion_ha_voter_journal_root_mismatch|readiness_mismatch/);

for (const tamper of [
  { trusted_runtime_ha_observer_sha256: H('f') },
  { promotion_signer_authority_root_sha256: H('f') },
  { promotion_signer_authority_epoch: PROMOTION_AUTH_EPOCH + 1 },
  { promotion_signature_quorum: PROMOTION_QUORUM + 1 },
]) {
  assert.throws(() => verifyTechnicalPromotionCertificate({ ...cert, ...tamper }, { readiness: ready, now: NOW + 1000 }), /promotion_certificate_hash_mismatch/);
}

const boundaryBody = { ...cert, grants_external_rights: true };
delete boundaryBody.certificate_sha256;
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.keys(value).sort().reduce((o, k) => { o[k] = stable(value[k]); return o; }, {});
  return value;
}
const boundaryTamper = { ...boundaryBody, certificate_sha256: crypto.createHash('sha256').update(JSON.stringify(stable(boundaryBody))).digest('hex') };
assert.throws(() => verifyTechnicalPromotionCertificate(boundaryTamper, { readiness: ready, now: NOW + 1000 }), /boundary_invalid/);

console.log('G-BANK sovereign v2 promotion certificate quorum/observer-pin tests: PASS');
