'use strict';

const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('./canonical');
const { publicKeyBinding } = require('./external-signing');

function positiveInt(name, value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 1) throw new Error(`${name}_invalid`);
  return n;
}

function normalizePromotionSignerAuthority(raw = {}) {
  const authorityEpoch = positiveInt('promotion_signer_authority_epoch', raw.authority_epoch);
  if (!Array.isArray(raw.signers)) throw new Error('promotion_signer_authority_signers_required');
  const seenIds = new Set();
  const seenKeys = new Set();
  const signers = raw.signers.map(value => {
    const signerId = String(value?.signer_id || '').trim();
    if (!signerId || signerId.length > 128 || seenIds.has(signerId)) throw new Error('promotion_signer_id_invalid_or_duplicate');
    const status = String(value?.status || '').toUpperCase();
    if (status !== 'ACTIVE') throw new Error('promotion_signer_must_be_active');
    const publicKeyPem = String(value?.public_key_pem || '');
    const keyBinding = publicKeyBinding(publicKeyPem);
    if (seenKeys.has(keyBinding)) throw new Error('promotion_signer_key_duplicate');
    seenIds.add(signerId);
    seenKeys.add(keyBinding);
    return Object.freeze({ signer_id: signerId, status: 'ACTIVE', public_key_pem: publicKeyPem, key_binding_sha256: keyBinding });
  }).sort((a, b) => a.signer_id.localeCompare(b.signer_id));
  if (signers.length < 3) throw new Error('promotion_signer_authority_minimum_three_required');
  const quorum = positiveInt('promotion_signer_quorum', raw.quorum);
  if (quorum < 2 || quorum > signers.length || quorum <= Math.floor(signers.length / 2)) throw new Error('promotion_signer_quorum_must_be_strict_majority');
  const body = {
    schema: 'g-bank-promotion-signer-authority/v2',
    authority_epoch: authorityEpoch,
    quorum,
    signers,
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
  };
  return Object.freeze({ ...body, authority_root_sha256: sha256(canonicalJson(body)) });
}

function verifyPromotionSignatureQuorum({ request, certificate, authority, bundle, now = Date.now(), max_age_ms = 5 * 60 * 1000 } = {}) {
  const normalized = authority?.schema === 'g-bank-promotion-signer-authority/v2' ? normalizePromotionSignerAuthority(authority) : normalizePromotionSignerAuthority(authority || {});
  if (normalized.authority_root_sha256 !== String(certificate?.promotion_signer_authority_root_sha256 || '').toLowerCase()) throw new Error('promotion_signer_authority_root_mismatch');
  if (normalized.quorum !== Number(certificate?.promotion_signature_quorum)) throw new Error('promotion_signer_quorum_certificate_mismatch');
  if (normalized.authority_epoch !== Number(certificate?.promotion_signer_authority_epoch)) throw new Error('promotion_signer_authority_epoch_mismatch');
  if (!request || request.certificate_sha256 !== certificate?.certificate_sha256) throw new Error('promotion_quorum_request_certificate_mismatch');
  if (!bundle || bundle.schema !== 'g-bank-promotion-signature-bundle/v2') throw new Error('promotion_signature_bundle_required');
  if (bundle.source !== 'VERIFIED_EXTERNAL_SIGNER_QUORUM') throw new Error('promotion_signature_bundle_source_invalid');
  if (bundle.signing_request_sha256 !== request.signing_request_sha256 || bundle.certificate_sha256 !== certificate.certificate_sha256) throw new Error('promotion_signature_bundle_binding_mismatch');
  if (!Array.isArray(bundle.signatures)) throw new Error('promotion_signature_bundle_signatures_required');

  const byId = new Map(normalized.signers.map(s => [s.signer_id, s]));
  const usedIds = new Set();
  const usedKeys = new Set();
  const valid = [];
  const payload = Buffer.from(canonicalJson(request));
  for (const entry of bundle.signatures) {
    const signerId = String(entry?.signer_id || '');
    const configured = byId.get(signerId);
    if (!configured || usedIds.has(signerId)) throw new Error('promotion_signature_bundle_signer_invalid_or_duplicate');
    const algorithm = String(entry?.algorithm || '').toUpperCase();
    if (!['ED25519', 'ECDSA-SHA256', 'RSA-SHA256'].includes(algorithm)) throw new Error('promotion_signature_bundle_algorithm_not_allowed');
    const publicKeyPem = String(entry?.public_key_pem || '');
    const binding = publicKeyBinding(publicKeyPem);
    if (binding !== configured.key_binding_sha256 || binding !== String(entry?.key_binding_sha256 || '').toLowerCase()) throw new Error('promotion_signature_bundle_key_mismatch');
    if (usedKeys.has(binding)) throw new Error('promotion_signature_bundle_key_duplicate');
    const signedAt = Date.parse(entry?.signed_at);
    const requestedAt = Date.parse(request.requested_at);
    if (!Number.isFinite(signedAt) || !Number.isFinite(requestedAt) || signedAt < requestedAt - 30000 || signedAt > now + 30000 || now - signedAt > max_age_ms) throw new Error('promotion_signature_bundle_time_invalid');
    let signature;
    try { signature = Buffer.from(String(entry?.signature_base64 || ''), 'base64'); } catch { throw new Error('promotion_signature_bundle_encoding_invalid'); }
    if (!signature.length) throw new Error('promotion_signature_bundle_encoding_invalid');
    let ok = false;
    try {
      const key = crypto.createPublicKey(publicKeyPem);
      ok = algorithm === 'ED25519' ? crypto.verify(null, payload, key, signature) : crypto.verify('sha256', payload, key, signature);
    } catch { ok = false; }
    if (!ok) throw new Error('promotion_signature_bundle_signature_invalid');
    const receipt = String(entry?.signer_receipt_sha256 || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(receipt)) throw new Error('promotion_signature_bundle_signer_receipt_invalid');
    usedIds.add(signerId);
    usedKeys.add(binding);
    valid.push(Object.freeze({ signer_id: signerId, key_binding_sha256: binding, algorithm, signed_at: new Date(signedAt).toISOString(), signer_receipt_sha256: receipt }));
  }
  if (valid.length < normalized.quorum) throw new Error('promotion_signature_quorum_not_met');
  const body = {
    schema: 'g-bank-promotion-signature-quorum-proof/v2',
    certificate_sha256: certificate.certificate_sha256,
    signing_request_sha256: request.signing_request_sha256,
    authority_root_sha256: normalized.authority_root_sha256,
    authority_epoch: normalized.authority_epoch,
    quorum: normalized.quorum,
    valid_signer_count: valid.length,
    signers: valid.sort((a, b) => a.signer_id.localeCompare(b.signer_id)),
    verified_at: new Date(now).toISOString(),
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
  };
  return Object.freeze({ ...body, proof_sha256: sha256(canonicalJson(body)) });
}

module.exports = { normalizePromotionSignerAuthority, verifyPromotionSignatureQuorum };
