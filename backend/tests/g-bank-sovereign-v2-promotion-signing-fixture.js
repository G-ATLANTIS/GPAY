'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { publicKeyBinding } = require('../g-bank-sovereign-v2/external-signing');
const { createPromotionSigningRequest } = require('../g-bank-sovereign-v2/promotion-signing');

function createSyntheticPromotionSigner(signer_id = 'SIGNER:PROMOTION:TEST') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return Object.freeze({ signer_id, public_key_pem: publicKeyPem, privateKey, key_binding_sha256: publicKeyBinding(publicKeyPem) });
}

function configureSyntheticPromotionSignature({ root, env, certificate, promotionSigner, now }) {
  if (!root || !env || !certificate || !promotionSigner?.privateKey || !Number.isFinite(Number(now))) throw new Error('synthetic_promotion_signature_fixture_invalid');
  if (certificate.trusted_signing_key_binding_sha256 !== promotionSigner.key_binding_sha256) throw new Error('synthetic_promotion_signer_binding_mismatch');
  const request = createPromotionSigningRequest({ certificate, now });
  const evidence = Object.freeze({
    schema: 'g-bank-external-promotion-signature-evidence/v2',
    source: 'VERIFIED_EXTERNAL_SIGNER',
    signing_request_sha256: request.signing_request_sha256,
    certificate_sha256: certificate.certificate_sha256,
    algorithm: 'ED25519',
    public_key_pem: promotionSigner.public_key_pem,
    key_binding_sha256: promotionSigner.key_binding_sha256,
    signed_at: new Date(Number(now) + 1000).toISOString(),
    signer_receipt_sha256: sha256(`test-promotion-signer-receipt:${certificate.certificate_sha256}`),
    signature_base64: crypto.sign(null, Buffer.from(canonicalJson(request)), promotionSigner.privateKey).toString('base64'),
  });
  const requestPath = path.join(root, `promotion-signing-request-${certificate.certificate_sha256.slice(0, 12)}.json`);
  const evidencePath = path.join(root, `promotion-signature-evidence-${certificate.certificate_sha256.slice(0, 12)}.json`);
  fs.writeFileSync(requestPath, JSON.stringify(request, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  fs.writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  env.G_BANK_RUNTIME_PROMOTION_SIGNING_REQUEST_FILE = requestPath;
  env.G_BANK_RUNTIME_PROMOTION_SIGNATURE_EVIDENCE_FILE = evidencePath;
  return Object.freeze({ request, evidence, request_path: requestPath, evidence_path: evidencePath });
}

function configureSyntheticPromotionQuorum({ root, env, certificate, authority, promotionSigners, request, now }) {
  if (!root || !env || !certificate || !authority || !Array.isArray(promotionSigners) || !request || !Number.isFinite(Number(now))) throw new Error('synthetic_promotion_quorum_fixture_invalid');
  if (certificate.promotion_signer_authority_root_sha256 !== authority.authority_root_sha256) throw new Error('synthetic_promotion_quorum_authority_mismatch');
  if (certificate.promotion_signer_authority_epoch !== authority.authority_epoch || certificate.promotion_signature_quorum !== authority.quorum) throw new Error('synthetic_promotion_quorum_policy_mismatch');
  if (request.certificate_sha256 !== certificate.certificate_sha256) throw new Error('synthetic_promotion_quorum_request_mismatch');
  const configured = new Map(authority.signers.map(s => [s.signer_id, s]));
  const selected = promotionSigners.slice(0, authority.quorum);
  if (selected.length < authority.quorum) throw new Error('synthetic_promotion_quorum_not_enough_signers');
  const signedAt = new Date(Number(now) + 1000).toISOString();
  const payload = Buffer.from(canonicalJson(request));
  const signatures = selected.map(signer => {
    const allowed = configured.get(signer.signer_id);
    if (!allowed || allowed.key_binding_sha256 !== signer.key_binding_sha256 || !signer.privateKey) throw new Error('synthetic_promotion_quorum_signer_not_authorized');
    return Object.freeze({
      signer_id: signer.signer_id,
      algorithm: 'ED25519',
      public_key_pem: signer.public_key_pem,
      key_binding_sha256: signer.key_binding_sha256,
      signed_at: signedAt,
      signer_receipt_sha256: sha256(`test-promotion-quorum-receipt:${signer.signer_id}:${certificate.certificate_sha256}`),
      signature_base64: crypto.sign(null, payload, signer.privateKey).toString('base64'),
    });
  });
  const bundle = Object.freeze({
    schema: 'g-bank-promotion-signature-bundle/v2',
    source: 'VERIFIED_EXTERNAL_SIGNER_QUORUM',
    signing_request_sha256: request.signing_request_sha256,
    certificate_sha256: certificate.certificate_sha256,
    signatures,
  });
  const authorityPath = path.join(root, `promotion-signer-authority-${certificate.certificate_sha256.slice(0, 12)}.json`);
  const bundlePath = path.join(root, `promotion-signature-bundle-${certificate.certificate_sha256.slice(0, 12)}.json`);
  fs.writeFileSync(authorityPath, JSON.stringify(authority, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  fs.writeFileSync(bundlePath, JSON.stringify(bundle, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  env.G_BANK_RUNTIME_PROMOTION_SIGNER_AUTHORITY_FILE = authorityPath;
  env.G_BANK_RUNTIME_PROMOTION_SIGNATURE_BUNDLE_FILE = bundlePath;
  return Object.freeze({ authority, bundle, authority_path: authorityPath, bundle_path: bundlePath });
}

module.exports = { createSyntheticPromotionSigner, configureSyntheticPromotionSignature, configureSyntheticPromotionQuorum };
