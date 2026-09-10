'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { publicKeyBinding } = require('../g-bank-sovereign-v2/external-signing');
const { normalizePromotionSignerAuthority, verifyPromotionSignatureQuorum } = require('../g-bank-sovereign-v2/promotion-signer-authority');

const NOW = Date.parse('2026-09-10T13:10:00.000Z');
const H = c => c.repeat(64);

function signer(id) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const public_key_pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return { signer_id: id, status: 'ACTIVE', public_key_pem, privateKey, key_binding_sha256: publicKeyBinding(public_key_pem) };
}

function fixture() {
  const signers = [signer('PROMOTION:A'), signer('PROMOTION:B'), signer('PROMOTION:C')];
  const authority = normalizePromotionSignerAuthority({
    authority_epoch: 4,
    quorum: 2,
    signers: signers.map(({ privateKey, key_binding_sha256, ...rest }) => rest),
  });
  const certificate = {
    certificate_sha256: H('1'),
    promotion_signer_authority_root_sha256: authority.authority_root_sha256,
    promotion_signer_authority_epoch: authority.authority_epoch,
    promotion_signature_quorum: authority.quorum,
  };
  const request = {
    schema: 'g-bank-promotion-signing-request/v2',
    certificate_sha256: certificate.certificate_sha256,
    signing_request_sha256: H('2'),
    requested_at: new Date(NOW).toISOString(),
  };
  function entry(s, signedAt = NOW + 1000) {
    return {
      signer_id: s.signer_id,
      algorithm: 'ED25519',
      public_key_pem: s.public_key_pem,
      key_binding_sha256: s.key_binding_sha256,
      signed_at: new Date(signedAt).toISOString(),
      signer_receipt_sha256: sha256(`receipt:${s.signer_id}`),
      signature_base64: crypto.sign(null, Buffer.from(canonicalJson(request)), s.privateKey).toString('base64'),
    };
  }
  return { signers, authority, certificate, request, entry };
}

(() => {
  const f = fixture();
  const bundle = {
    schema: 'g-bank-promotion-signature-bundle/v2',
    source: 'VERIFIED_EXTERNAL_SIGNER_QUORUM',
    signing_request_sha256: f.request.signing_request_sha256,
    certificate_sha256: f.certificate.certificate_sha256,
    signatures: [f.entry(f.signers[0]), f.entry(f.signers[1])],
  };
  const proof = verifyPromotionSignatureQuorum({ request: f.request, certificate: f.certificate, authority: f.authority, bundle, now: NOW + 2000 });
  assert.equal(proof.valid_signer_count, 2);
  assert.equal(proof.quorum, 2);
  assert.equal(proof.authority_root_sha256, f.authority.authority_root_sha256);
  assert.deepEqual(proof.signers.map(s => s.signer_id), ['PROMOTION:A', 'PROMOTION:B']);
  assert.equal(proof.grants_external_rights, false);
  assert.equal(proof.permits_value_movement_by_itself, false);
  assert.match(proof.proof_sha256, /^[0-9a-f]{64}$/);
})();

(() => {
  const f = fixture();
  const bundle = {
    schema: 'g-bank-promotion-signature-bundle/v2', source: 'VERIFIED_EXTERNAL_SIGNER_QUORUM',
    signing_request_sha256: f.request.signing_request_sha256, certificate_sha256: f.certificate.certificate_sha256,
    signatures: [f.entry(f.signers[0])],
  };
  assert.throws(() => verifyPromotionSignatureQuorum({ request: f.request, certificate: f.certificate, authority: f.authority, bundle, now: NOW + 2000 }), /promotion_signature_quorum_not_met/);
})();

(() => {
  const f = fixture();
  const first = f.entry(f.signers[0]);
  const bundle = {
    schema: 'g-bank-promotion-signature-bundle/v2', source: 'VERIFIED_EXTERNAL_SIGNER_QUORUM',
    signing_request_sha256: f.request.signing_request_sha256, certificate_sha256: f.certificate.certificate_sha256,
    signatures: [first, { ...first }],
  };
  assert.throws(() => verifyPromotionSignatureQuorum({ request: f.request, certificate: f.certificate, authority: f.authority, bundle, now: NOW + 2000 }), /promotion_signature_bundle_signer_invalid_or_duplicate/);
})();

(() => {
  const f = fixture();
  const forged = { ...f.entry(f.signers[1]), signature_base64: Buffer.from('forged').toString('base64') };
  const bundle = {
    schema: 'g-bank-promotion-signature-bundle/v2', source: 'VERIFIED_EXTERNAL_SIGNER_QUORUM',
    signing_request_sha256: f.request.signing_request_sha256, certificate_sha256: f.certificate.certificate_sha256,
    signatures: [f.entry(f.signers[0]), forged],
  };
  assert.throws(() => verifyPromotionSignatureQuorum({ request: f.request, certificate: f.certificate, authority: f.authority, bundle, now: NOW + 2000 }), /promotion_signature_bundle_signature_invalid/);
})();

(() => {
  const f = fixture();
  const attacker = signer('PROMOTION:ATTACKER');
  const bundle = {
    schema: 'g-bank-promotion-signature-bundle/v2', source: 'VERIFIED_EXTERNAL_SIGNER_QUORUM',
    signing_request_sha256: f.request.signing_request_sha256, certificate_sha256: f.certificate.certificate_sha256,
    signatures: [f.entry(f.signers[0]), f.entry(attacker)],
  };
  assert.throws(() => verifyPromotionSignatureQuorum({ request: f.request, certificate: f.certificate, authority: f.authority, bundle, now: NOW + 2000 }), /promotion_signature_bundle_signer_invalid_or_duplicate/);
})();

(() => {
  const f = fixture();
  const bundle = {
    schema: 'g-bank-promotion-signature-bundle/v2', source: 'VERIFIED_EXTERNAL_SIGNER_QUORUM',
    signing_request_sha256: f.request.signing_request_sha256, certificate_sha256: f.certificate.certificate_sha256,
    signatures: [f.entry(f.signers[0]), f.entry(f.signers[1])],
  };
  assert.throws(() => verifyPromotionSignatureQuorum({ request: f.request, certificate: { ...f.certificate, promotion_signer_authority_root_sha256: H('9') }, authority: f.authority, bundle, now: NOW + 2000 }), /promotion_signer_authority_root_mismatch/);
  assert.throws(() => verifyPromotionSignatureQuorum({ request: f.request, certificate: { ...f.certificate, promotion_signer_authority_epoch: 5 }, authority: f.authority, bundle, now: NOW + 2000 }), /promotion_signer_authority_epoch_mismatch/);
})();

(() => {
  const f = fixture();
  const bundle = {
    schema: 'g-bank-promotion-signature-bundle/v2', source: 'VERIFIED_EXTERNAL_SIGNER_QUORUM',
    signing_request_sha256: f.request.signing_request_sha256, certificate_sha256: f.certificate.certificate_sha256,
    signatures: [f.entry(f.signers[0], NOW - 400000), f.entry(f.signers[1])],
  };
  assert.throws(() => verifyPromotionSignatureQuorum({ request: f.request, certificate: f.certificate, authority: f.authority, bundle, now: NOW + 2000 }), /promotion_signature_bundle_time_invalid/);
})();

(() => {
  const a = signer('PROMOTION:A');
  const b = signer('PROMOTION:B');
  assert.throws(() => normalizePromotionSignerAuthority({ authority_epoch: 1, quorum: 2, signers: [
    { signer_id: a.signer_id, status: 'ACTIVE', public_key_pem: a.public_key_pem },
    { signer_id: b.signer_id, status: 'ACTIVE', public_key_pem: b.public_key_pem },
  ] }), /promotion_signer_authority_minimum_three_required/);
})();

console.log('G-BANK sovereign v2 promotion signer quorum tests: PASS');
