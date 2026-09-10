'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function hash64(name, value) {
  const v = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) throw new Error(`${name}_invalid`);
  return v;
}

function verifyReadiness(readiness) {
  if (!readiness || readiness.schema !== 'g-bank-sovereign-readiness/v2') throw new Error('readiness_required');
  const required = [
    'static_configuration_ready',
    'external_transport_verified',
    'prudential_controls_verified',
    'operational_controls_verified',
    'customer_monitoring_verified',
    'direct_live_ready',
    'value_movement_permitted_by_readiness',
  ];
  if (readiness.state !== 'DIRECT_LIVE_READY' || required.some(k => readiness[k] !== true)) {
    throw new Error('direct_live_readiness_not_satisfied');
  }
  return readiness;
}

function createTechnicalPromotionCertificate({
  readiness,
  checkpoint,
  governance,
  evidence_bindings,
  trusted_signing_key_binding_sha256,
  ttl_seconds = 120,
  now = Date.now(),
}) {
  verifyReadiness(readiness);
  if (!checkpoint || checkpoint.schema !== 'g-bank-sovereign-state-checkpoint/v2') throw new Error('checkpoint_required');
  const stateRoot = hash64('state_root_sha256', checkpoint.state_root_sha256);
  const policyHash = hash64('policy_sha256', governance?.policy_sha256);
  const authorityHash = hash64('authority_set_sha256', governance?.authority_set_sha256);
  const signingKeyHash = hash64('trusted_signing_key_binding_sha256', trusted_signing_key_binding_sha256);
  const evidence = evidence_bindings || {};
  const bindings = {
    legal_authorization_evidence_sha256: hash64('legal_authorization_evidence_sha256', evidence.legal_authorization_evidence_sha256),
    scheme_participation_evidence_sha256: hash64('scheme_participation_evidence_sha256', evidence.scheme_participation_evidence_sha256),
    settlement_access_evidence_sha256: hash64('settlement_access_evidence_sha256', evidence.settlement_access_evidence_sha256),
    production_identity_evidence_sha256: hash64('production_identity_evidence_sha256', evidence.production_identity_evidence_sha256),
    transport_preflight_receipt_sha256: hash64('transport_preflight_receipt_sha256', evidence.transport_preflight_receipt_sha256),
    prudential_audit_sha256: hash64('prudential_audit_sha256', evidence.prudential_audit_sha256),
    operational_resilience_sha256: hash64('operational_resilience_sha256', evidence.operational_resilience_sha256),
    treasury_assessment_sha256: hash64('treasury_assessment_sha256', evidence.treasury_assessment_sha256),
    customer_monitoring_audit_sha256: hash64('customer_monitoring_audit_sha256', evidence.customer_monitoring_audit_sha256),
  };
  const ttl = Number(ttl_seconds);
  if (!Number.isSafeInteger(ttl) || ttl < 30 || ttl > 300) throw new Error('promotion_certificate_ttl_invalid');

  const body = {
    schema: 'g-bank-technical-promotion-certificate/v2',
    state: 'TECHNICAL_GATES_SATISFIED',
    readiness_snapshot_sha256: sha256(canonicalJson(readiness)),
    state_root_sha256: stateRoot,
    policy_sha256: policyHash,
    authority_set_sha256: authorityHash,
    trusted_signing_key_binding_sha256: signingKeyHash,
    evidence_bindings: bindings,
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + ttl * 1000).toISOString(),
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
    requires_runtime_reverification: true,
  };
  return Object.freeze({ ...body, certificate_sha256: sha256(canonicalJson(body)) });
}

function verifyTechnicalPromotionCertificate(certificate, { readiness, now = Date.now() } = {}) {
  if (!certificate || certificate.schema !== 'g-bank-technical-promotion-certificate/v2') throw new Error('promotion_certificate_required');
  const supplied = hash64('certificate_sha256', certificate.certificate_sha256);
  const { certificate_sha256, ...body } = certificate;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('promotion_certificate_hash_mismatch');
  if (certificate.state !== 'TECHNICAL_GATES_SATISFIED') throw new Error('promotion_certificate_state_invalid');
  if (certificate.grants_external_rights !== false || certificate.permits_value_movement_by_itself !== false || certificate.requires_runtime_reverification !== true) {
    throw new Error('promotion_certificate_boundary_invalid');
  }
  const issued = Date.parse(certificate.issued_at);
  const expires = Date.parse(certificate.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > now + 30000 || expires <= now || expires - issued > 300000) {
    throw new Error('promotion_certificate_expired_or_invalid');
  }
  if (readiness) {
    verifyReadiness(readiness);
    if (certificate.readiness_snapshot_sha256 !== sha256(canonicalJson(readiness))) throw new Error('promotion_certificate_readiness_mismatch');
  }
  return true;
}

module.exports = {
  createTechnicalPromotionCertificate,
  verifyTechnicalPromotionCertificate,
  verifyReadiness,
};
