'use strict';

const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('./canonical');

function hash64(name, value) {
  const v = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) throw new Error(`${name}_invalid`);
  return v;
}

function publicKeyBinding(publicKeyPem) {
  let key;
  try { key = crypto.createPublicKey(publicKeyPem); }
  catch { throw new Error('signing_public_key_invalid'); }
  const der = key.export({ type: 'spki', format: 'der' });
  return sha256(der);
}

function createSigningRequest({ prepared, settlement_authorization_sha256, now = Date.now() }) {
  if (!prepared || prepared.schema !== 'g-bank-sovereign-prepared-payment/v2') throw new Error('prepared_payment_required');
  const instructionHash = hash64('instruction_sha256', prepared.instruction?.instruction_sha256);
  const messageHash = hash64('message_sha256', prepared.iso20022?.document_sha256);
  const preparationHash = hash64('preparation_sha256', prepared.preparation_sha256);
  const authorizationHash = hash64('settlement_authorization_sha256', settlement_authorization_sha256);
  const body = {
    schema: 'g-bank-settlement-signing-request/v2',
    preparation_sha256: preparationHash,
    instruction_sha256: instructionHash,
    message_type: String(prepared.iso20022?.message_type || ''),
    message_sha256: messageHash,
    settlement_authorization_sha256: authorizationHash,
    requested_at: new Date(now).toISOString(),
  };
  if (!body.message_type || body.message_type.length > 64) throw new Error('message_type_invalid');
  return Object.freeze({ ...body, signing_request_sha256: sha256(canonicalJson(body)) });
}

function verifyRequest(request) {
  if (!request || request.schema !== 'g-bank-settlement-signing-request/v2') throw new Error('signing_request_invalid');
  const supplied = hash64('signing_request_sha256', request.signing_request_sha256);
  const { signing_request_sha256, ...body } = request;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('signing_request_hash_mismatch');
  return request;
}

function verifySignature(algorithm, payload, publicKeyPem, signature) {
  const key = crypto.createPublicKey(publicKeyPem);
  if (algorithm === 'ED25519') return crypto.verify(null, payload, key, signature);
  if (algorithm === 'ECDSA-SHA256' || algorithm === 'RSA-SHA256') return crypto.verify('sha256', payload, key, signature);
  throw new Error('signing_algorithm_not_allowed');
}

function verifyExternalSigningEvidence(request, evidence, {
  trusted_key_bindings = [],
  now = Date.now(),
  max_age_ms = 5 * 60 * 1000,
} = {}) {
  verifyRequest(request);
  if (!evidence || evidence.schema !== 'g-bank-external-signature-evidence/v2') throw new Error('external_signature_evidence_required');
  if (evidence.source !== 'VERIFIED_EXTERNAL_SIGNER') throw new Error('external_signature_source_invalid');
  if (evidence.signing_request_sha256 !== request.signing_request_sha256) throw new Error('external_signature_request_mismatch');
  if (evidence.message_sha256 !== request.message_sha256) throw new Error('external_signature_message_mismatch');
  const algorithm = String(evidence.algorithm || '').toUpperCase();
  if (!['ED25519', 'ECDSA-SHA256', 'RSA-SHA256'].includes(algorithm)) throw new Error('signing_algorithm_not_allowed');
  const publicKeyPem = String(evidence.public_key_pem || '');
  const binding = publicKeyBinding(publicKeyPem);
  if (binding !== String(evidence.key_binding_sha256 || '').toLowerCase()) throw new Error('signing_key_binding_mismatch');
  const trusted = new Set((trusted_key_bindings || []).map(v => String(v).toLowerCase()));
  if (!trusted.size || !trusted.has(binding)) throw new Error('signing_key_not_trusted');
  const signedAt = Date.parse(evidence.signed_at);
  if (!Number.isFinite(signedAt) || signedAt > now + 30000 || now - signedAt > max_age_ms) throw new Error('external_signature_stale');

  let signature;
  try { signature = Buffer.from(String(evidence.signature_base64 || ''), 'base64'); }
  catch { throw new Error('external_signature_encoding_invalid'); }
  if (!signature.length) throw new Error('external_signature_encoding_invalid');
  const payload = Buffer.from(canonicalJson(request));
  if (!verifySignature(algorithm, payload, publicKeyPem, signature)) throw new Error('external_signature_invalid');

  const body = {
    schema: 'g-bank-external-signature-proof/v2',
    signing_request_sha256: request.signing_request_sha256,
    preparation_sha256: request.preparation_sha256,
    instruction_sha256: request.instruction_sha256,
    message_sha256: request.message_sha256,
    algorithm,
    key_binding_sha256: binding,
    signer_receipt_sha256: hash64('signer_receipt_sha256', evidence.signer_receipt_sha256),
    verified_at: new Date(now).toISOString(),
  };
  return Object.freeze({ ...body, proof_sha256: sha256(canonicalJson(body)) });
}

function createSignedSettlementEnvelope({ request, signingProof }) {
  verifyRequest(request);
  if (!signingProof || signingProof.schema !== 'g-bank-external-signature-proof/v2') throw new Error('signing_proof_required');
  if (signingProof.signing_request_sha256 !== request.signing_request_sha256 || signingProof.message_sha256 !== request.message_sha256) {
    throw new Error('signing_proof_request_mismatch');
  }
  const supplied = hash64('signing_proof_sha256', signingProof.proof_sha256);
  const { proof_sha256, ...proofBody } = signingProof;
  if (sha256(canonicalJson(proofBody)) !== supplied) throw new Error('signing_proof_hash_mismatch');
  const body = {
    schema: 'g-bank-signed-settlement-envelope/v2',
    signing_request_sha256: request.signing_request_sha256,
    message_sha256: request.message_sha256,
    instruction_sha256: request.instruction_sha256,
    key_binding_sha256: signingProof.key_binding_sha256,
    signature_proof_sha256: signingProof.proof_sha256,
    settlement_authorization_sha256: request.settlement_authorization_sha256,
  };
  return Object.freeze({ ...body, envelope_sha256: sha256(canonicalJson(body)) });
}

module.exports = {
  publicKeyBinding,
  createSigningRequest,
  verifyRequest,
  verifyExternalSigningEvidence,
  createSignedSettlementEnvelope,
};
