'use strict';

const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('./canonical');
const { publicKeyBinding } = require('./external-signing');
const { verifyTechnicalPromotionCertificate } = require('./promotion-certificate');

function hash64(name, value) {
  const v = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) throw new Error(`${name}_invalid`);
  return v;
}

function positiveInt(name, value, min = 1) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < min) throw new Error(`${name}_invalid`);
  return n;
}

function createPromotionSigningRequest({ certificate, now = Date.now() } = {}) {
  verifyTechnicalPromotionCertificate(certificate, { now });
  const body = {
    schema: 'g-bank-promotion-signing-request/v2',
    certificate_sha256: hash64('promotion_signing_certificate_sha256', certificate.certificate_sha256),
    state_root_sha256: hash64('promotion_signing_state_root_sha256', certificate.state_root_sha256),
    policy_sha256: hash64('promotion_signing_policy_sha256', certificate.policy_sha256),
    authority_set_sha256: hash64('promotion_signing_authority_set_sha256', certificate.authority_set_sha256),
    trusted_signing_key_binding_sha256: hash64('promotion_signing_trusted_key_sha256', certificate.trusted_signing_key_binding_sha256),
    trusted_runtime_ha_observer_sha256: hash64('promotion_signing_runtime_observer_sha256', certificate.trusted_runtime_ha_observer_sha256),
    promotion_signer_authority_root_sha256: hash64('promotion_signing_authority_root_sha256', certificate.promotion_signer_authority_root_sha256),
    promotion_signer_authority_epoch: positiveInt('promotion_signing_authority_epoch', certificate.promotion_signer_authority_epoch),
    promotion_signature_quorum: positiveInt('promotion_signing_quorum', certificate.promotion_signature_quorum, 2),
    ha_voter_journal_root_sha256: hash64('promotion_signing_ha_voter_journal_root_sha256', certificate.ha_voter_journal_root_sha256),
    ha_cluster_authority_root_sha256: hash64('promotion_signing_ha_cluster_authority_root_sha256', certificate.ha_cluster_authority_root_sha256),
    certificate_expires_at: new Date(Date.parse(certificate.expires_at)).toISOString(),
    requested_at: new Date(now).toISOString(),
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
  };
  return Object.freeze({ ...body, signing_request_sha256: sha256(canonicalJson(body)) });
}

function verifyPromotionSigningRequest(request, certificate) {
  if (!request || request.schema !== 'g-bank-promotion-signing-request/v2') throw new Error('promotion_signing_request_required');
  const supplied = hash64('promotion_signing_request_sha256', request.signing_request_sha256);
  const { signing_request_sha256, ...body } = request;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('promotion_signing_request_hash_mismatch');
  if (request.grants_external_rights !== false || request.permits_value_movement_by_itself !== false) throw new Error('promotion_signing_request_boundary_invalid');
  if (certificate) {
    if (request.certificate_sha256 !== certificate.certificate_sha256) throw new Error('promotion_signing_certificate_mismatch');
    if (request.trusted_signing_key_binding_sha256 !== certificate.trusted_signing_key_binding_sha256) throw new Error('promotion_signing_trusted_key_mismatch');
    if (request.trusted_runtime_ha_observer_sha256 !== certificate.trusted_runtime_ha_observer_sha256) throw new Error('promotion_signing_observer_mismatch');
    if (request.promotion_signer_authority_root_sha256 !== certificate.promotion_signer_authority_root_sha256) throw new Error('promotion_signing_authority_root_mismatch');
    if (request.promotion_signer_authority_epoch !== certificate.promotion_signer_authority_epoch) throw new Error('promotion_signing_authority_epoch_mismatch');
    if (request.promotion_signature_quorum !== certificate.promotion_signature_quorum) throw new Error('promotion_signing_quorum_mismatch');
    if (request.state_root_sha256 !== certificate.state_root_sha256 || request.policy_sha256 !== certificate.policy_sha256 || request.authority_set_sha256 !== certificate.authority_set_sha256) throw new Error('promotion_signing_governance_binding_mismatch');
    if (request.ha_voter_journal_root_sha256 !== certificate.ha_voter_journal_root_sha256 || request.ha_cluster_authority_root_sha256 !== certificate.ha_cluster_authority_root_sha256) throw new Error('promotion_signing_ha_binding_mismatch');
    if (request.certificate_expires_at !== certificate.expires_at) throw new Error('promotion_signing_expiry_binding_mismatch');
  }
  return request;
}

function verifyAlgorithmSignature(algorithm, payload, publicKeyPem, signature) {
  const key = crypto.createPublicKey(publicKeyPem);
  if (algorithm === 'ED25519') return crypto.verify(null, payload, key, signature);
  if (algorithm === 'ECDSA-SHA256' || algorithm === 'RSA-SHA256') return crypto.verify('sha256', payload, key, signature);
  throw new Error('promotion_signing_algorithm_not_allowed');
}

function verifyExternalPromotionSignatureEvidence({ request, certificate, evidence, now = Date.now(), max_age_ms = 5 * 60 * 1000 } = {}) {
  verifyTechnicalPromotionCertificate(certificate, { now });
  verifyPromotionSigningRequest(request, certificate);
  if (!evidence || evidence.schema !== 'g-bank-external-promotion-signature-evidence/v2') throw new Error('promotion_signature_evidence_required');
  if (evidence.source !== 'VERIFIED_EXTERNAL_SIGNER') throw new Error('promotion_signature_source_invalid');
  if (evidence.signing_request_sha256 !== request.signing_request_sha256 || evidence.certificate_sha256 !== certificate.certificate_sha256) throw new Error('promotion_signature_request_mismatch');
  const algorithm = String(evidence.algorithm || '').toUpperCase();
  if (!['ED25519', 'ECDSA-SHA256', 'RSA-SHA256'].includes(algorithm)) throw new Error('promotion_signing_algorithm_not_allowed');
  const publicKeyPem = String(evidence.public_key_pem || '');
  const binding = publicKeyBinding(publicKeyPem);
  if (binding !== String(evidence.key_binding_sha256 || '').toLowerCase()) throw new Error('promotion_signature_key_binding_mismatch');
  if (binding !== certificate.trusted_signing_key_binding_sha256) throw new Error('promotion_signature_key_not_certificate_trusted');
  const signedAt = Date.parse(evidence.signed_at);
  const requestedAt = Date.parse(request.requested_at);
  if (!Number.isFinite(signedAt) || !Number.isFinite(requestedAt) || signedAt < requestedAt - 30000 || signedAt > now + 30000 || now - signedAt > max_age_ms) throw new Error('promotion_signature_stale_or_invalid_time');
  let signature;
  try { signature = Buffer.from(String(evidence.signature_base64 || ''), 'base64'); } catch { throw new Error('promotion_signature_encoding_invalid'); }
  if (!signature.length) throw new Error('promotion_signature_encoding_invalid');
  const payload = Buffer.from(canonicalJson(request));
  let valid = false;
  try { valid = verifyAlgorithmSignature(algorithm, payload, publicKeyPem, signature); } catch (err) { if (err.message === 'promotion_signing_algorithm_not_allowed') throw err; valid = false; }
  if (!valid) throw new Error('promotion_signature_invalid');

  const body = {
    schema: 'g-bank-external-promotion-signature-proof/v2',
    certificate_sha256: certificate.certificate_sha256,
    signing_request_sha256: request.signing_request_sha256,
    algorithm,
    key_binding_sha256: binding,
    signer_receipt_sha256: hash64('promotion_signer_receipt_sha256', evidence.signer_receipt_sha256),
    signed_at: new Date(signedAt).toISOString(),
    verified_at: new Date(now).toISOString(),
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
  };
  return Object.freeze({ ...body, proof_sha256: sha256(canonicalJson(body)) });
}

module.exports = { createPromotionSigningRequest, verifyPromotionSigningRequest, verifyExternalPromotionSignatureEvidence };
