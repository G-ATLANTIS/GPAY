'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { canonicalJson } = require('../g-bank-sovereign-v2/canonical');
const {
  publicKeyBinding,
  createSigningRequest,
  verifyExternalSigningEvidence,
  createSignedSettlementEnvelope,
} = require('../g-bank-sovereign-v2/external-signing');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T22:00:00.000Z');

function prepared() {
  return {
    schema: 'g-bank-sovereign-prepared-payment/v2',
    preparation_sha256: H('a'),
    instruction: { instruction_sha256: H('b') },
    iso20022: {
      message_type: 'pacs.008.001.08',
      document_sha256: H('c'),
    },
  };
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
const keyBinding = publicKeyBinding(publicKeyPem);
const request = createSigningRequest({
  prepared: prepared(),
  settlement_authorization_sha256: H('d'),
  now: NOW,
});
const signature = crypto.sign(null, Buffer.from(canonicalJson(request)), privateKey).toString('base64');
const evidence = {
  schema: 'g-bank-external-signature-evidence/v2',
  source: 'VERIFIED_EXTERNAL_SIGNER',
  signing_request_sha256: request.signing_request_sha256,
  message_sha256: request.message_sha256,
  algorithm: 'ED25519',
  public_key_pem: publicKeyPem,
  key_binding_sha256: keyBinding,
  signature_base64: signature,
  signer_receipt_sha256: H('e'),
  signed_at: new Date(NOW - 1000).toISOString(),
};

const proof = verifyExternalSigningEvidence(request, evidence, {
  trusted_key_bindings: [keyBinding],
  now: NOW,
});
assert.equal(proof.message_sha256, request.message_sha256);
assert.equal(proof.key_binding_sha256, keyBinding);
assert.equal(proof.algorithm, 'ED25519');

const envelope = createSignedSettlementEnvelope({ request, signingProof: proof });
assert.equal(envelope.message_sha256, request.message_sha256);
assert.equal(envelope.signature_proof_sha256, proof.proof_sha256);
assert.match(envelope.envelope_sha256, /^[0-9a-f]{64}$/);

assert.throws(() => verifyExternalSigningEvidence(request, evidence, {
  trusted_key_bindings: [H('f')],
  now: NOW,
}), /signing_key_not_trusted/);

const badSignature = { ...evidence, signature_base64: Buffer.alloc(64, 1).toString('base64') };
assert.throws(() => verifyExternalSigningEvidence(request, badSignature, {
  trusted_key_bindings: [keyBinding],
  now: NOW,
}), /external_signature_invalid/);

const tamperedRequest = { ...request, message_sha256: H('9') };
assert.throws(() => verifyExternalSigningEvidence(tamperedRequest, evidence, {
  trusted_key_bindings: [keyBinding],
  now: NOW,
}), /signing_request_hash_mismatch/);

const staleEvidence = { ...evidence, signed_at: new Date(NOW - 10 * 60 * 1000).toISOString() };
assert.throws(() => verifyExternalSigningEvidence(request, staleEvidence, {
  trusted_key_bindings: [keyBinding],
  now: NOW,
}), /external_signature_stale/);

const alteredProof = { ...proof, key_binding_sha256: H('1') };
assert.throws(() => createSignedSettlementEnvelope({ request, signingProof: alteredProof }), /signing_proof_hash_mismatch/);

console.log('G-BANK sovereign v2 external signing tests: PASS');
