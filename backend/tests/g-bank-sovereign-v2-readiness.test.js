'use strict';

const assert = require('node:assert/strict');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { assessSovereignReadiness } = require('../g-bank-sovereign-v2/readiness');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T09:45:00.000Z');

function hashed(schema, hashField, extra = {}) {
  const body = { schema, state: 'PASS', ...extra };
  return Object.freeze({ ...body, [hashField]: sha256(canonicalJson(body)) });
}

const base = {
  G_BANK_ENABLE_LIVE: 'true',
  G_BANK_EXTERNAL_ACTIONS_ENABLED: 'true',
  G_BANK_DIRECT_SETTLEMENT_ENABLED: 'true',
  G_BANK_SIMULATED_LIVE_SUCCESS: 'false',
  G_BANK_SOVEREIGN_APPROVAL_SECRET: '0123456789abcdef0123456789abcdef',
  G_BANK_GOVERNANCE_REQUIRED: 'true',
  G_BANK_SETTLEMENT_TRANSPORT_MODULE: '/authorized/transport.js',
  G_BANK_SETTLEMENT_AUTHORIZATION_SHA256: H('a'),
};

const governance = {
  policy_sha256: H('7'),
  authority_set_sha256: H('8'),
  policy_epoch: 3,
  authority_epoch: 4,
  normal_quorum: 1,
  high_value_quorum: 2,
};

const prudential = {
  safeguarding: hashed('g-bank-safeguarding-assessment/v2', 'assessment_sha256'),
  liquidity: hashed('g-bank-liquidity-assessment/v2', 'assessment_sha256'),
  invariant_audit: hashed('g-bank-sovereign-invariant-audit/v2', 'audit_sha256'),
  operational_resilience: hashed('g-bank-operational-resilience-assessment/v2', 'assessment_sha256'),
  treasury: hashed('g-bank-treasury-position/v2', 'assessment_sha256'),
};

const monitoringAudit = hashed('g-bank-monitoring-fleet-audit/v2', 'audit_sha256', {
  policy_sha256: H('4'), policy_epoch: 2, monitorable_customer_count: 3, assessment_count: 3,
  clear_customer_count: 2, review_required_customer_count: 1, suspended_customer_count: 0,
  reasons: [], audited_at: new Date(NOW).toISOString(), regulatory_determination_made: false,
  external_report_submitted: false, permits_value_movement_by_itself: false,
});

const recoveryAudit = hashed('g-bank-recovery-readiness-audit/v2', 'audit_sha256', {
  generation: 7, manifest_sha256: H('9'), recovery_anchor_head_sha256: H('1'),
  recovery_anchor_record_sha256: H('2'), checkpoint_state_root_sha256: H('3'),
  restore_verification_sha256: H('4'), max_age_ms: 900000, checks: { synthetic_recovery_snapshot: true },
  grants_external_rights: false, activates_live_execution: false, permits_value_movement: false,
  audited_at: new Date(NOW).toISOString(),
});

function makeHAAudit(extra = {}) {
  return hashed('g-bank-ha-readiness-audit/v2', 'audit_sha256', {
    cluster_sha256: H('5'), cluster_epoch: 1, active_voter_count: 3, quorum: 2,
    latest_term: 8, leader_node_id: 'NODE:A', fence_record_sha256: H('6'),
    fence_valid_until: new Date(NOW + 120000).toISOString(), latest_commit_index: 42,
    latest_commit_sha256: H('7'), replicated_state_root_sha256: H('3'),
    checkpoint_state_root_sha256: H('3'), reasons: [], audited_at: new Date(NOW).toISOString(),
    grants_external_rights: false, permits_value_movement_by_itself: false,
    distributed_network_verified: false, ...extra,
  });
}

const haAudit = makeHAAudit();
const transportPreflight = {
  environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST',
  settlement_system: 'TIPS', external_receipt_sha256: H('1'),
};

const completeEnv = {
  ...base,
  G_BANK_LEGAL_AUTHORIZATION_EVIDENCE_SHA256: H('c'),
  G_BANK_SCHEME_PARTICIPATION_EVIDENCE_SHA256: H('d'),
  G_BANK_SETTLEMENT_ACCESS_EVIDENCE_SHA256: H('e'),
  G_BANK_PRODUCTION_IDENTITY_EVIDENCE_SHA256: H('f'),
  G_BANK_PRUDENTIAL_AUDIT_SHA256: prudential.invariant_audit.audit_sha256,
  G_BANK_OPERATIONAL_RESILIENCE_SHA256: prudential.operational_resilience.assessment_sha256,
  G_BANK_TREASURY_ASSESSMENT_SHA256: prudential.treasury.assessment_sha256,
  G_BANK_CUSTOMER_MONITORING_AUDIT_SHA256: monitoringAudit.audit_sha256,
  G_BANK_RECOVERY_AUDIT_SHA256: recoveryAudit.audit_sha256,
  G_BANK_HA_AUDIT_SHA256: haAudit.audit_sha256,
};

function assess(overrides = {}) {
  return assessSovereignReadiness({ env: completeEnv, governance, prudential, monitoringAudit, recoveryAudit, haAudit, transportPreflight, now: NOW, ...overrides });
}

const blocked = assessSovereignReadiness({ env: base, governance, prudential, monitoringAudit, recoveryAudit, haAudit, transportPreflight, now: NOW });
assert.equal(blocked.direct_live_ready, false);
assert.equal(blocked.state, 'DIRECT_LIVE_BLOCKED');
assert.equal(blocked.checks.legal_authorization_evidence_binding_present, false);

const ready = assess();
assert.equal(ready.direct_live_ready, true);
assert.equal(ready.external_transport_verified, true);
assert.equal(ready.prudential_controls_verified, true);
assert.equal(ready.operational_controls_verified, true);
assert.equal(ready.customer_monitoring_verified, true);
assert.equal(ready.recovery_controls_verified, true);
assert.equal(ready.ha_controls_verified, true);
assert.equal(ready.checks.ha_checkpoint_matches_recovery, true);
assert.equal(ready.checks.ha_fence_current, true);
assert.equal(ready.evidence_bindings.ha_audit_sha256, haAudit.audit_sha256);
assert.equal(ready.ha_checkpoint_state_root_sha256, H('3'));

const noHA = assess({ haAudit: null });
assert.equal(noHA.direct_live_ready, false);
assert.equal(noHA.ha_controls_verified, false);
assert.equal(noHA.checks.ha_audit_pass, false);

const tamperedHA = assess({ haAudit: { ...haAudit, latest_commit_index: 999 } });
assert.equal(tamperedHA.direct_live_ready, false);
assert.equal(tamperedHA.checks.ha_audit_pass, false);

const differentRootHA = makeHAAudit({ replicated_state_root_sha256: H('a'), checkpoint_state_root_sha256: H('a') });
const differentRootEnv = { ...completeEnv, G_BANK_HA_AUDIT_SHA256: differentRootHA.audit_sha256 };
const differentRoot = assess({ env: differentRootEnv, haAudit: differentRootHA });
assert.equal(differentRoot.direct_live_ready, false);
assert.equal(differentRoot.checks.ha_checkpoint_matches_recovery, false);

const expiredHA = makeHAAudit({ fence_valid_until: new Date(NOW - 1).toISOString() });
const expiredEnv = { ...completeEnv, G_BANK_HA_AUDIT_SHA256: expiredHA.audit_sha256 };
const expired = assess({ env: expiredEnv, haAudit: expiredHA });
assert.equal(expired.direct_live_ready, false);
assert.equal(expired.checks.ha_fence_current, false);

const noRecovery = assess({ recoveryAudit: null });
assert.equal(noRecovery.direct_live_ready, false);
assert.equal(noRecovery.recovery_controls_verified, false);

const tamperedRecovery = assess({ recoveryAudit: { ...recoveryAudit, generation: 999 } });
assert.equal(tamperedRecovery.direct_live_ready, false);
assert.equal(tamperedRecovery.checks.recovery_audit_pass, false);

const noMonitoring = assess({ monitoringAudit: null });
assert.equal(noMonitoring.direct_live_ready, false);
assert.equal(noMonitoring.customer_monitoring_verified, false);

const noPrudential = assess({ prudential: null });
assert.equal(noPrudential.direct_live_ready, false);
assert.equal(noPrudential.prudential_controls_verified, false);
assert.equal(noPrudential.operational_controls_verified, false);

const failedTreasury = assess({ prudential: { ...prudential, treasury: { ...prudential.treasury, state: 'BLOCK' } } });
assert.equal(failedTreasury.direct_live_ready, false);
assert.equal(failedTreasury.checks.treasury_pass, false);

const frozen = assess({ prudential: { ...prudential, operational_resilience: { ...prudential.operational_resilience, state: 'BLOCK' } } });
assert.equal(frozen.direct_live_ready, false);
assert.equal(frozen.operational_controls_verified, false);

const weakQuorum = assess({ governance: { ...governance, high_value_quorum: 1 } });
assert.equal(weakQuorum.direct_live_ready, false);
assert.equal(weakQuorum.checks.high_value_quorum_dual_control, false);

const fake = assess({ env: { ...completeEnv, G_BANK_SIMULATED_LIVE_SUCCESS: 'true' } });
assert.equal(fake.direct_live_ready, false);
assert.equal(fake.checks.simulated_live_success_forbidden, false);

console.log('G-BANK sovereign v2 readiness tests: PASS');
