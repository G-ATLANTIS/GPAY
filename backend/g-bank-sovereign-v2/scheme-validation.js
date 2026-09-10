'use strict';

const { canonicalJson, sha256 } = require('../g-bank-live-v1/canonical');
const { assertSha256, assertFresh } = require('./compliance');

function verifySchemeValidationEvidence(evidence, message, {
  now = Date.now(),
  max_age_ms = 15 * 60 * 1000,
  require_external = true,
} = {}) {
  if (!message?.document_sha256 || !message?.message_type) throw new Error('iso20022_message_required');
  if (!evidence || typeof evidence !== 'object') throw new Error('scheme_validation_evidence_required');
  if (evidence.result !== 'PASS') throw new Error('scheme_validation_not_passed');
  if (evidence.message_sha256 !== message.document_sha256) throw new Error('scheme_validation_message_hash_mismatch');
  if (evidence.message_type !== message.message_type) throw new Error('scheme_validation_message_type_mismatch');
  if (evidence.scheme !== 'SCT' && evidence.scheme !== 'SCT_INST') throw new Error('scheme_validation_scheme_invalid');
  if (require_external && evidence.validation_level !== 'EXTERNAL_SCHEME_VALIDATED') {
    throw new Error('external_scheme_validation_required');
  }
  assertFresh('scheme_validation', evidence.observed_at, now, max_age_ms);
  assertSha256('scheme_validator_binding_sha256', evidence.validator_binding_sha256);
  assertSha256('scheme_validation_receipt_sha256', evidence.validation_receipt_sha256);

  const proof = {
    schema: 'g-bank-scheme-validation-proof/v2',
    scheme: evidence.scheme,
    message_type: message.message_type,
    message_sha256: message.document_sha256,
    validation_level: evidence.validation_level,
    validator_binding_sha256: evidence.validator_binding_sha256,
    validation_receipt_sha256: evidence.validation_receipt_sha256,
    evidence_observed_at: evidence.observed_at,
  };
  proof.proof_sha256 = sha256(canonicalJson(proof));
  return Object.freeze(proof);
}

module.exports = { verifySchemeValidationEvidence };
