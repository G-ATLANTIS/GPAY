'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { canonicalJson } = require('../g-bank-sovereign-v2/canonical');
const { publicKeyBinding } = require('../g-bank-sovereign-v2/external-signing');
const { createTechnicalPromotionCertificate } = require('../g-bank-sovereign-v2/promotion-certificate');
const { normalizePromotionSignerAuthority } = require('../g-bank-sovereign-v2/promotion-signer-authority');
const { createPromotionSigningRequest, verifyPromotionSigningRequest, verifyExternalPromotionSignatureEvidence } = require('../g-bank-sovereign-v2/promotion-signing');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T12:15:00.000Z');

function makeSigner(signerId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return { signer_id: signerId, publicKey, privateKey, publicKeyPem, keyBinding: publicKeyBinding(publicKeyPem) };
}

function fixture() {
  const primary = makeSigner('SIGNER:PROMOTION:A');
  const secondary = makeSigner('SIGNER:PROMOTION:B');
  const tertiary = makeSigner('SIGNER:PROMOTION:C');
  const promotionSignerAuthority = normalizePromotionSignerAuthority({
    authority_epoch: 1,
    quorum: 2,
    signers: [primary, secondary, tertiary].map(s => ({ signer_id: s.signer_id, status: 'ACTIVE', public_key_pem: s.publicKeyPem })),
  });
  const evidence_bindings = {
    legal_authorization_evidence_sha256: H('1'), scheme_participation_evidence_sha256: H('2'), settlement_access_evidence_sha256: H('3'),
    production_identity_evidence_sha256: H('4'), transport_preflight_receipt_sha256: H('5'), prudential_audit_sha256: H('6'),
    operational_resilience_sha256: H('7'), treasury_assessment_sha256: H('8'), customer_monitoring_audit_sha256: H('9'),
    recovery_audit_sha256: H('a'), ha_audit_sha256: H('b'), ha_deployment_audit_sha256: H('c'),
  };
  const readiness = {
    schema: 'g-bank-sovereign-readiness/v2', state: 'DIRECT_LIVE_READY', static_configuration_ready: true,
    external_transport_verified: true, prudential_controls_verified: true, operational_controls_verified: true,
    customer_monitoring_verified: true, recovery_controls_verified: true, ha_controls_verified: true, ha_deployment_verified: true,
    direct_live_ready: true, value_movement_permitted_by_readiness: true, checks: { promotion_signing_fixture: true }, evidence_bindings,
    recovery_checkpoint_state_root_sha256: H('d'), ha_checkpoint_state_root_sha256: H('d'), ha_voter_journal_root_sha256: H('e'),
    ha_cluster_authority_root_sha256: H('f'), ha_fence_valid_until: new Date(NOW + 120000).toISOString(),
  };
  const certificate = createTechnicalPromotionCertificate({
    readiness, checkpoint: { schema: 'g-bank-sovereign-state-checkpoint/v2', state_root_sha256: H('d') },
    governance: { policy_sha256: H('1'), authority_set_sha256: H('2') }, evidence_bindings,
    trusted_signing_key_binding_sha256: primary.keyBinding,
    trusted_runtime_ha_observer_sha256: H('3'),
    promotion_signer_authority_root_sha256: promotionSignerAuthority.authority_root_sha256,
    promotion_signer_authority_epoch: promotionSignerAuthority.authority_epoch,
    promotion_signature_quorum: promotionSignerAuthority.quorum,
    ttl_seconds: 120, now: NOW,
  });
  const request = createPromotionSigningRequest({ certificate, now: NOW + 1000 });
  const signature = crypto.sign(null, Buffer.from(canonicalJson(request)), primary.privateKey).toString('base64');
  const evidence = {
    schema: 'g-bank-external-promotion-signature-evidence/v2', source: 'VERIFIED_EXTERNAL_SIGNER',
    signing_request_sha256: request.signing_request_sha256, certificate_sha256: certificate.certificate_sha256,
    algorithm: 'ED25519', public_key_pem: primary.publicKeyPem, key_binding_sha256: primary.keyBinding,
    signed_at: new Date(NOW + 2000).toISOString(), signer_receipt_sha256: H('4'), signature_base64: signature,
  };
  return { primary, secondary, tertiary, promotionSignerAuthority, readiness, certificate, request, evidence };
}

(() => {
  const f = fixture();
  assert.equal(verifyPromotionSigningRequest(f.request, f.certificate), f.request);
  assert.equal(f.request.promotion_signer_authority_root_sha256, f.promotionSignerAuthority.authority_root_sha256);
  assert.equal(f.request.promotion_signer_authority_epoch, 1);
  assert.equal(f.request.promotion_signature_quorum, 2);
  const proof = verifyExternalPromotionSignatureEvidence({ request: f.request, certificate: f.certificate, evidence: f.evidence, now: NOW + 3000 });
  assert.equal(proof.certificate_sha256, f.certificate.certificate_sha256);
  assert.equal(proof.key_binding_sha256, f.primary.keyBinding);
  assert.equal(proof.grants_external_rights, false);
  assert.equal(proof.permits_value_movement_by_itself, false);
  assert.match(proof.proof_sha256, /^[0-9a-f]{64}$/);
})();

(() => {
  const f = fixture();
  const attacker = makeSigner('SIGNER:PROMOTION:ATTACKER');
  const attackerEvidence = {
    ...f.evidence,
    public_key_pem: attacker.publicKeyPem,
    key_binding_sha256: attacker.keyBinding,
    signature_base64: crypto.sign(null, Buffer.from(canonicalJson(f.request)), attacker.privateKey).toString('base64'),
  };
  assert.throws(() => verifyExternalPromotionSignatureEvidence({ request: f.request, certificate: f.certificate, evidence: attackerEvidence, now: NOW + 3000 }), /promotion_signature_key_not_certificate_trusted/);
})();

(() => {
  const f = fixture();
  const tamperedRequest = { ...f.request, promotion_signature_quorum: 3 };
  assert.throws(() => verifyPromotionSigningRequest(tamperedRequest, f.certificate), /promotion_signing_request_hash_mismatch/);
  assert.throws(() => verifyExternalPromotionSignatureEvidence({ request: f.request, certificate: f.certificate, evidence: { ...f.evidence, signature_base64: Buffer.from('forged').toString('base64') }, now: NOW + 3000 }), /promotion_signature_invalid/);
})();

(() => {
  const f = fixture();
  assert.throws(() => verifyExternalPromotionSignatureEvidence({ request: f.request, certificate: f.certificate, evidence: f.evidence, now: NOW + 6 * 60 * 1000 }), /promotion_signature_stale_or_invalid_time|promotion_certificate_expired_or_invalid/);
})();

console.log('G-BANK sovereign v2 detached external promotion signing quorum-bound tests: PASS');
