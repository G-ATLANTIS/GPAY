'use strict';

// Canonical, closed set of terminal execution states for the
// G_VERIFIED_EXECUTION_SPINE. Every call to executeVerified() MUST resolve to
// exactly one of these. VERIFIED_SUCCESS is the only non-failure state and is
// unreachable without collected evidence (see spine.js).
const RESULT_STATE = Object.freeze({
  VERIFIED_SUCCESS: 'VERIFIED_SUCCESS',
  DENIED_POLICY: 'DENIED_POLICY',
  DENIED_SCOPE: 'DENIED_SCOPE',
  DENIED_AUTHORIZATION: 'DENIED_AUTHORIZATION',
  NO_VERIFIED_PATH: 'NO_VERIFIED_PATH',
  PROVIDER_FAILURE: 'PROVIDER_FAILURE',
  EXECUTION_UNVERIFIED: 'EXECUTION_UNVERIFIED',
  READBACK_MISMATCH: 'READBACK_MISMATCH',
  REPLAY_REJECTED: 'REPLAY_REJECTED',
  STALE_STATE_REJECTED: 'STALE_STATE_REJECTED',
  INTERNAL_FAIL_CLOSED: 'INTERNAL_FAIL_CLOSED',
});

const SUCCESS_STATE = RESULT_STATE.VERIFIED_SUCCESS;

const FAILURE_STATES = Object.freeze(
  Object.values(RESULT_STATE).filter((s) => s !== SUCCESS_STATE),
);

// Ordered pipeline. Enforcement walks these in order and cannot skip forward.
const STAGE = Object.freeze([
  'REQUEST',
  'VERIFY_SCOPE',
  'CHECK_PATH',
  'DISCOVER_CAPABILITY',
  'POLICY_CHECK',
  'AUTHORIZATION',
  'EXECUTE',
  'VERIFY_READBACK',
  'RECEIPT',
  'AUDIT',
  'COMMIT_STATE',
]);

// Capability assurance ladder. Promotion is never automatic; a connector must
// re-evidence its level on every discover()/execute() call.
const ASSURANCE = Object.freeze({
  L0: 'L0', // declared / configured only
  L1: 'L1', // local implementation verified
  L2: 'L2', // authenticated external read verified
  L3: 'L3', // authenticated external write verified
  L4: 'L4', // external write + independent/readback verification
});

const ASSURANCE_RANK = Object.freeze({ L0: 0, L1: 1, L2: 2, L3: 3, L4: 4 });

function assuranceAtLeast(have, want) {
  return (ASSURANCE_RANK[have] ?? -1) >= (ASSURANCE_RANK[want] ?? 99);
}

function minAssurance(a, b) {
  return (ASSURANCE_RANK[a] ?? -1) <= (ASSURANCE_RANK[b] ?? -1) ? a : b;
}

// Verification methods, weakest to strongest.
const VERIFICATION_METHOD = Object.freeze({
  NONE: 'NONE',
  LOCAL_STATE_READBACK: 'LOCAL_STATE_READBACK',
  PROVIDER_RECEIPT_ONLY: 'PROVIDER_RECEIPT_ONLY',
  AUTHENTICATED_PROVIDER_READBACK: 'AUTHENTICATED_PROVIDER_READBACK',
});

const CANONICAL_COMMIT_STATUS = Object.freeze({
  NOT_COMMITTED: 'NOT_COMMITTED',
  COMMITTED: 'COMMITTED',
  QUARANTINED_RECONCILE: 'QUARANTINED_RECONCILE',
});

module.exports = {
  RESULT_STATE,
  SUCCESS_STATE,
  FAILURE_STATES,
  STAGE,
  ASSURANCE,
  ASSURANCE_RANK,
  assuranceAtLeast,
  minAssurance,
  VERIFICATION_METHOD,
  CANONICAL_COMMIT_STATUS,
};
