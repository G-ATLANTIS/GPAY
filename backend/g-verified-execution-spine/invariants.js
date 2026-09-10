'use strict';

const { RESULT_STATE, SUCCESS_STATE, CANONICAL_COMMIT_STATUS, VERIFICATION_METHOD } = require('./states');

// Machine-testable invariants over a VerifiedExecutionResult. checkResult()
// returns { ok, violations } . These are asserted by the test suite for every
// path and can also be run by the CLI as a self-check.
//
//   NO_AUTHORIZATION            => NO_EXECUTION
//   NO_VERIFIED_PATH            => NO_EXECUTION
//   FAILED_POLICY              => NO_EXECUTION
//   FAILED_EXECUTION           => NO_CANONICAL_SUCCESS
//   FAILED_REQUIRED_READBACK   => NO_CANONICAL_SUCCESS
//   AUDIT_FAILURE              => FAIL_CLOSED
//   UNKNOWN_PROVIDER_STATE     => UNVERIFIED (never SUCCESS)
//   SIMULATED_SUCCESS          => NEVER VERIFIED_SUCCESS

const PRE_EXECUTION_DENIALS = new Set([
  RESULT_STATE.DENIED_SCOPE,
  RESULT_STATE.DENIED_POLICY,
  RESULT_STATE.DENIED_AUTHORIZATION,
  RESULT_STATE.NO_VERIFIED_PATH,
  RESULT_STATE.STALE_STATE_REJECTED,
]);

function checkResult(r) {
  const v = [];
  if (!r || typeof r !== 'object') return { ok: false, violations: ['result_not_object'] };

  // 1. Denials before EXECUTE must never carry an execution receipt.
  if (PRE_EXECUTION_DENIALS.has(r.state)) {
    if (r.provider_request_id) v.push(`${r.state}_carried_provider_request_id`);
    if (r.execution_result) v.push(`${r.state}_carried_execution_result`);
    if (r.canonical_commit_status === CANONICAL_COMMIT_STATUS.COMMITTED) {
      v.push(`${r.state}_marked_committed`);
    }
  }

  // 2. Only VERIFIED_SUCCESS may be COMMITTED / evidence_complete.
  if (r.canonical_commit_status === CANONICAL_COMMIT_STATUS.COMMITTED && r.state !== SUCCESS_STATE) {
    v.push('committed_without_verified_success');
  }
  if (r.evidence_complete === true && r.state !== SUCCESS_STATE) {
    v.push('evidence_complete_without_verified_success');
  }

  // 3. VERIFIED_SUCCESS requires the full evidence set.
  if (r.state === SUCCESS_STATE) {
    const required = [
      'execution_id',
      'request_id',
      'idempotency_key_sha256',
      'actor',
      'requested_capability',
      'resolved_path',
      'policy_hash',
      'authorization_evidence',
      'pre_state_hash',
      'execution_timestamp',
      'provider',
      'provider_request_id',
      'execution_result',
      'verification_method',
      'post_state_hash',
      'audit_entry_hash',
      'result_sha256',
    ];
    for (const key of required) {
      if (r[key] === null || r[key] === undefined || r[key] === '') {
        v.push(`verified_success_missing_${key}`);
      }
    }
    if (r.canonical_commit_status !== CANONICAL_COMMIT_STATUS.COMMITTED) {
      v.push('verified_success_not_committed');
    }
    if (r.verification_method === VERIFICATION_METHOD.NONE) {
      v.push('verified_success_with_no_verification_method');
    }
    if (r.evidence_complete !== true) v.push('verified_success_evidence_incomplete');
  }

  // 4. Uncertain execution can never be a success.
  if (
    [RESULT_STATE.EXECUTION_UNVERIFIED, RESULT_STATE.READBACK_MISMATCH, RESULT_STATE.PROVIDER_FAILURE].includes(r.state)
  ) {
    if (r.canonical_commit_status === CANONICAL_COMMIT_STATUS.COMMITTED) {
      v.push('uncertain_execution_committed');
    }
  }

  // 5. INTERNAL_FAIL_CLOSED must not be committed.
  if (r.state === RESULT_STATE.INTERNAL_FAIL_CLOSED && r.canonical_commit_status === CANONICAL_COMMIT_STATUS.COMMITTED) {
    v.push('internal_fail_closed_committed');
  }

  // 6. State must be in the closed set.
  if (!Object.values(RESULT_STATE).includes(r.state)) v.push(`unknown_result_state:${r.state}`);

  return { ok: v.length === 0, violations: v };
}

function assertResult(r) {
  const { ok, violations } = checkResult(r);
  if (!ok) throw new Error(`invariant_violation:${violations.join(';')}`);
  return true;
}

module.exports = { checkResult, assertResult, PRE_EXECUTION_DENIALS };
