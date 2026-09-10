'use strict';

// G_VERIFIED_EXECUTION_SPINE — the single canonical, deterministic, fail-closed
// enforcement path for state-changing −G operations.
//
//   REQUEST -> VERIFY_SCOPE -> CHECK_PATH -> DISCOVER_CAPABILITY -> POLICY_CHECK
//   -> AUTHORIZATION -> EXECUTE -> VERIFY_READBACK -> RECEIPT -> AUDIT
//   -> COMMIT_STATE
//
// No external action is represented as successful without verifiable evidence.
//   UNVERIFIED_EXTERNAL_EFFECT != CANONICAL_SUCCESS

const states = require('./states');
const { PolicyEngine } = require('./policy');
const { CapabilityRegistry } = require('./capability-registry');
const { SequenceStore } = require('./sequence-store');
const { createAuthorization, verifyAuthorization } = require('./authorization');
const { redact, assertNoSecrets, safeEvidence } = require('./redaction');
const { executeVerified, reconcile, normalizeRequest, requestCanonicalSha256, buildContext } = require('./spine');
const { checkResult, assertResult } = require('./invariants');
const { LocalFileCapability } = require('./connectors/local-file');
const { MollieSpineConnector } = require('./connectors/mollie-spine-connector');

module.exports = {
  ...states,
  PolicyEngine,
  CapabilityRegistry,
  SequenceStore,
  createAuthorization,
  verifyAuthorization,
  redact,
  assertNoSecrets,
  safeEvidence,
  executeVerified,
  reconcile,
  normalizeRequest,
  requestCanonicalSha256,
  buildContext,
  checkResult,
  assertResult,
  LocalFileCapability,
  MollieSpineConnector,
};
