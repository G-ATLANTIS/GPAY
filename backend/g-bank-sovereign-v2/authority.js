'use strict';

const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('./canonical');

function assertOperatorId(value) {
  const v = String(value || '');
  if (!/^[A-Za-z0-9:_-]{3,128}$/.test(v)) throw new Error('operator_id_invalid');
  return v;
}

function normalizeAuthoritySet(input = {}) {
  const epoch = Number(input.authority_epoch);
  if (!Number.isSafeInteger(epoch) || epoch < 1) throw new Error('authority_epoch_invalid');
  if (!Array.isArray(input.operators) || !input.operators.length) throw new Error('authority_operators_required');
  const seen = new Set();
  const operators = input.operators.map(op => {
    const operator_id = assertOperatorId(op.operator_id);
    if (seen.has(operator_id)) throw new Error('authority_operator_duplicate');
    seen.add(operator_id);
    const role = String(op.role || 'APPROVER').toUpperCase();
    if (!['APPROVER', 'SENIOR_APPROVER', 'SECURITY_OFFICER'].includes(role)) throw new Error('authority_role_invalid');
    const status = String(op.status || 'ACTIVE').toUpperCase();
    if (!['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(status)) throw new Error('authority_status_invalid');
    const public_key_pem = String(op.public_key_pem || '');
    let key;
    try { key = crypto.createPublicKey(public_key_pem); } catch { throw new Error('authority_public_key_invalid'); }
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('authority_key_must_be_ed25519');
    return { operator_id, role, status, public_key_pem };
  }).sort((a, b) => a.operator_id.localeCompare(b.operator_id));
  const set = { schema: 'g-bank-sovereign-authority-set/v2', authority_epoch: epoch, operators };
  set.authority_set_sha256 = sha256(canonicalJson(set));
  return Object.freeze(set);
}

function approvalPayload({ prepared, schemeValidationEvidence, riskDecision, idempotencyKey, authorityEpoch }) {
  if (!prepared?.preparation_sha256) throw new Error('prepared_payment_required');
  if (!schemeValidationEvidence?.validation_receipt_sha256) throw new Error('scheme_validation_evidence_required');
  if (!riskDecision?.decision_sha256 || riskDecision.decision !== 'ALLOW') throw new Error('risk_allow_decision_required');
  const body = {
    schema: 'g-bank-sovereign-quorum-approval-payload/v2',
    preparation_sha256: prepared.preparation_sha256,
    instruction_sha256: prepared.instruction.instruction_sha256,
    message_sha256: prepared.iso20022.document_sha256,
    compliance_proof_sha256: prepared.compliance_proof.proof_sha256,
    scheme_validation_receipt_sha256: String(schemeValidationEvidence.validation_receipt_sha256).toLowerCase(),
    risk_decision_sha256: riskDecision.decision_sha256,
    policy_sha256: riskDecision.policy_sha256,
    policy_epoch: riskDecision.policy_epoch,
    authority_epoch: authorityEpoch,
    amount_minor: prepared.instruction.amount_minor,
    currency: prepared.instruction.currency,
    beneficiary_binding_sha256: prepared.instruction.beneficiary_binding_sha256,
    idempotency_key_sha256: sha256(String(idempotencyKey || '')),
  };
  if (!idempotencyKey) throw new Error('idempotency_key_required');
  body.payload_sha256 = sha256(canonicalJson(body));
  return Object.freeze(body);
}

function verifyQuorum({ prepared, schemeValidationEvidence, riskDecision, idempotencyKey, authoritySet, signatures, now = Date.now(), max_age_ms = 5 * 60 * 1000 }) {
  const set = normalizeAuthoritySet(authoritySet);
  const payload = approvalPayload({ prepared, schemeValidationEvidence, riskDecision, idempotencyKey, authorityEpoch: set.authority_epoch });
  if (!Array.isArray(signatures)) throw new Error('approval_signatures_required');
  const active = new Map(set.operators.filter(o => o.status === 'ACTIVE').map(o => [o.operator_id, o]));
  const accepted = [];
  const used = new Set();
  for (const sig of signatures) {
    const operatorId = assertOperatorId(sig.operator_id);
    if (used.has(operatorId)) throw new Error('approval_operator_duplicate');
    used.add(operatorId);
    const op = active.get(operatorId);
    if (!op) throw new Error('approval_operator_not_active');
    const observed = Date.parse(sig.signed_at);
    if (!Number.isFinite(observed) || observed > now + 30000 || now - observed > max_age_ms) throw new Error('approval_signature_stale');
    if (sig.payload_sha256 !== payload.payload_sha256) throw new Error('approval_payload_hash_mismatch');
    let signature;
    try { signature = Buffer.from(String(sig.signature_base64 || ''), 'base64'); } catch { throw new Error('approval_signature_invalid'); }
    if (!signature.length || !crypto.verify(null, Buffer.from(payload.payload_sha256, 'utf8'), op.public_key_pem, signature)) {
      throw new Error('approval_signature_invalid');
    }
    accepted.push({ operator_id: operatorId, role: op.role, signed_at: new Date(observed).toISOString() });
  }
  const required = Number(riskDecision.required_quorum);
  if (!Number.isSafeInteger(required) || required < 1) throw new Error('risk_required_quorum_invalid');
  if (accepted.length < required) throw new Error('approval_quorum_not_met');
  if (required > 1 && !accepted.some(a => ['SENIOR_APPROVER', 'SECURITY_OFFICER'].includes(a.role))) {
    throw new Error('high_value_senior_approval_required');
  }
  const proof = {
    schema: 'g-bank-sovereign-quorum-proof/v2',
    payload_sha256: payload.payload_sha256,
    authority_set_sha256: set.authority_set_sha256,
    authority_epoch: set.authority_epoch,
    required_quorum: required,
    accepted_operators: accepted,
    verified_at: new Date(now).toISOString(),
  };
  proof.quorum_proof_sha256 = sha256(canonicalJson(proof));
  return Object.freeze(proof);
}

module.exports = { normalizeAuthoritySet, approvalPayload, verifyQuorum };
