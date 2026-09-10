'use strict';

const assert = require('node:assert/strict');
const {
  createTechnicalPromotionCertificate,
  verifyTechnicalPromotionCertificate,
} = require('../g-bank-sovereign-v2/promotion-certificate');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T22:30:00.000Z');

function readiness(overrides = {}) {
  return {
    schema: 'g-bank-sovereign-readiness/v2',
    state: 'DIRECT_LIVE_READY',
    static_configuration_ready: true,
    external_transport_verified: true,
    prudential_controls_verified: true,
    operational_controls_verified: true,
    customer_monitoring_verified: true,
    direct_live_ready: true,
    value_movement_permitted_by_readiness: true,
    checks: { synthetic_test_snapshot: true },
    ...overrides,
  };
}

const checkpoint = {
  schema: 'g-bank-sovereign-state-checkpoint/v2',
  state_root_sha256: H('a'),
};
const governance = {
  policy_sha256: H('b'),
  authority_set_sha256: H('c'),
};
const evidence_bindings = {
  legal_authorization_evidence_sha256: H('d'),
  scheme_participation_evidence_sha256: H('e'),
  settlement_access_evidence_sha256: H('f'),
  production_identity_evidence_sha256: H('1'),
  transport_preflight_receipt_sha256: H('2'),
  prudential_audit_sha256: H('3'),
  operational_resilience_sha256: H('4'),
  treasury_assessment_sha256: H('5'),
  customer_monitoring_audit_sha256: H('6'),
};

const ready = readiness();
const cert = createTechnicalPromotionCertificate({
  readiness: ready,
  checkpoint,
  governance,
  evidence_bindings,
  trusted_signing_key_binding_sha256: H('7'),
  ttl_seconds: 120,
  now: NOW,
});

assert.equal(cert.state, 'TECHNICAL_GATES_SATISFIED');
assert.equal(cert.grants_external_rights, false);
assert.equal(cert.permits_value_movement_by_itself, false);
assert.equal(cert.requires_runtime_reverification, true);
assert.equal(cert.evidence_bindings.customer_monitoring_audit_sha256, H('6'));
assert.match(cert.certificate_sha256, /^[0-9a-f]{64}$/);
assert.equal(verifyTechnicalPromotionCertificate(cert, { readiness: ready, now: NOW + 1000 }), true);

const tampered = { ...cert, state_root_sha256: H('8') };
assert.throws(() => verifyTechnicalPromotionCertificate(tampered, { readiness: ready, now: NOW + 1000 }), /hash_mismatch/);

assert.throws(() => verifyTechnicalPromotionCertificate(cert, { readiness: ready, now: NOW + 121000 }), /expired_or_invalid/);

assert.throws(() => createTechnicalPromotionCertificate({
  readiness: readiness({ direct_live_ready: false, state: 'DIRECT_LIVE_BLOCKED' }),
  checkpoint,
  governance,
  evidence_bindings,
  trusted_signing_key_binding_sha256: H('7'),
  now: NOW,
}), /direct_live_readiness_not_satisfied/);

assert.throws(() => createTechnicalPromotionCertificate({
  readiness: readiness({ customer_monitoring_verified: false }),
  checkpoint,
  governance,
  evidence_bindings,
  trusted_signing_key_binding_sha256: H('7'),
  now: NOW,
}), /direct_live_readiness_not_satisfied/);

assert.throws(() => createTechnicalPromotionCertificate({
  readiness: ready,
  checkpoint,
  governance,
  evidence_bindings: { ...evidence_bindings, customer_monitoring_audit_sha256: null },
  trusted_signing_key_binding_sha256: H('7'),
  now: NOW,
}), /customer_monitoring_audit_sha256_invalid/);

assert.throws(() => verifyTechnicalPromotionCertificate(cert, {
  readiness: readiness({ checks: { synthetic_test_snapshot: true, changed: true } }),
  now: NOW + 1000,
}), /readiness_mismatch/);

const boundaryTamperBody = { ...cert, grants_external_rights: true };
delete boundaryTamperBody.certificate_sha256;
const crypto = require('node:crypto');
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.keys(value).sort().reduce((o, k) => { o[k] = stable(value[k]); return o; }, {});
  return value;
}
const boundaryTamper = {
  ...boundaryTamperBody,
  certificate_sha256: crypto.createHash('sha256').update(JSON.stringify(stable(boundaryTamperBody))).digest('hex'),
};
assert.throws(() => verifyTechnicalPromotionCertificate(boundaryTamper, { readiness: ready, now: NOW + 1000 }), /boundary_invalid/);

console.log('G-BANK sovereign v2 promotion certificate tests: PASS');
