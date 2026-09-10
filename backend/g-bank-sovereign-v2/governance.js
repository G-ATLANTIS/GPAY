'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { evaluatePaymentPolicy } = require('./risk-policy');
const { verifyQuorum } = require('./authority');

function createGovernanceProof({
  prepared,
  schemeValidationEvidence,
  idempotencyKey,
  policy,
  authoritySet,
  signatures,
  receiptRows = [],
  now = Date.now(),
}) {
  const riskDecision = evaluatePaymentPolicy({ prepared, policy, receiptRows, now });
  if (riskDecision.decision !== 'ALLOW') {
    const err = new Error('payment_policy_denied');
    err.reasons = riskDecision.reasons;
    throw err;
  }
  const quorumProof = verifyQuorum({
    prepared,
    schemeValidationEvidence,
    riskDecision,
    idempotencyKey,
    authoritySet,
    signatures,
    now,
  });
  const body = {
    schema: 'g-bank-sovereign-governance-proof/v2',
    preparation_sha256: prepared.preparation_sha256,
    instruction_sha256: prepared.instruction.instruction_sha256,
    risk_decision_sha256: riskDecision.decision_sha256,
    policy_sha256: riskDecision.policy_sha256,
    policy_epoch: riskDecision.policy_epoch,
    quorum_proof_sha256: quorumProof.quorum_proof_sha256,
    authority_set_sha256: quorumProof.authority_set_sha256,
    authority_epoch: quorumProof.authority_epoch,
    required_quorum: quorumProof.required_quorum,
    verified_at: new Date(now).toISOString(),
  };
  const proof = { ...body, governance_proof_sha256: sha256(canonicalJson(body)) };
  return Object.freeze({ ...proof, risk_decision: riskDecision, quorum_proof: quorumProof });
}

function verifyGovernanceProof(proof, { prepared, max_age_ms = 5 * 60 * 1000, now = Date.now() }) {
  if (!proof || proof.schema !== 'g-bank-sovereign-governance-proof/v2') throw new Error('governance_proof_required');
  if (proof.preparation_sha256 !== prepared.preparation_sha256) throw new Error('governance_preparation_mismatch');
  if (proof.instruction_sha256 !== prepared.instruction.instruction_sha256) throw new Error('governance_instruction_mismatch');
  if (proof.risk_decision?.decision !== 'ALLOW') throw new Error('governance_risk_not_allowed');
  if (proof.risk_decision_sha256 !== proof.risk_decision.decision_sha256) throw new Error('governance_risk_hash_mismatch');
  if (proof.quorum_proof_sha256 !== proof.quorum_proof?.quorum_proof_sha256) throw new Error('governance_quorum_hash_mismatch');
  if (proof.required_quorum !== proof.quorum_proof?.required_quorum) throw new Error('governance_quorum_mismatch');
  const verified = Date.parse(proof.verified_at);
  if (!Number.isFinite(verified) || verified > now + 30000 || now - verified > max_age_ms) throw new Error('governance_proof_stale');
  const body = {
    schema: proof.schema,
    preparation_sha256: proof.preparation_sha256,
    instruction_sha256: proof.instruction_sha256,
    risk_decision_sha256: proof.risk_decision_sha256,
    policy_sha256: proof.policy_sha256,
    policy_epoch: proof.policy_epoch,
    quorum_proof_sha256: proof.quorum_proof_sha256,
    authority_set_sha256: proof.authority_set_sha256,
    authority_epoch: proof.authority_epoch,
    required_quorum: proof.required_quorum,
    verified_at: proof.verified_at,
  };
  if (proof.governance_proof_sha256 !== sha256(canonicalJson(body))) throw new Error('governance_proof_hash_invalid');
  return true;
}

module.exports = { createGovernanceProof, verifyGovernanceProof };
