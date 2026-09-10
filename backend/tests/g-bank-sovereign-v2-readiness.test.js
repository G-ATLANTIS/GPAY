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
  G_BANK_ENABLE_LIVE: 'true', G_BANK_EXTERNAL_ACTIONS_ENABLED: 'true', G_BANK_DIRECT_SETTLEMENT_ENABLED: 'true',
  G_BANK_SIMULATED_LIVE_SUCCESS: 'false', G_BANK_SOVEREIGN_APPROVAL_SECRET: '0123456789abcdef0123456789abcdef',
  G_BANK_GOVERNANCE_REQUIRED: 'true', G_BANK_SETTLEMENT_TRANSPORT_MODULE: '/authorized/transport.js', G_BANK_SETTLEMENT_AUTHORIZATION_SHA256: H('a'),
};
const governance = { policy_sha256: H('7'), authority_set_sha256: H('8'), policy_epoch: 3, authority_epoch: 4, normal_quorum: 1, high_value_quorum: 2 };
const prudential = {
  safeguarding: hashed('g-bank-safeguarding-assessment/v2', 'assessment_sha256'), liquidity: hashed('g-bank-liquidity-assessment/v2', 'assessment_sha256'),
  invariant_audit: hashed('g-bank-sovereign-invariant-audit/v2', 'audit_sha256'), operational_resilience: hashed('g-bank-operational-resilience-assessment/v2', 'assessment_sha256'),
  treasury: hashed('g-bank-treasury-position/v2', 'assessment_sha256'),
};
const monitoringAudit = hashed('g-bank-monitoring-fleet-audit/v2', 'audit_sha256', {
  policy_sha256: H('4'), policy_epoch: 2, monitorable_customer_count: 3, assessment_count: 3, clear_customer_count: 2, review_required_customer_count: 1,
  suspended_customer_count: 0, reasons: [], audited_at: new Date(NOW).toISOString(), regulatory_determination_made: false, external_report_submitted: false, permits_value_movement_by_itself: false,
});
const recoveryAudit = hashed('g-bank-recovery-readiness-audit/v2', 'audit_sha256', {
  generation: 7, manifest_sha256: H('9'), recovery_anchor_head_sha256: H('1'), recovery_anchor_record_sha256: H('2'), checkpoint_state_root_sha256: H('3'),
  restore_verification_sha256: H('4'), max_age_ms: 900000, checks: { synthetic_recovery_snapshot: true }, grants_external_rights: false, activates_live_execution: false,
  permits_value_movement: false, audited_at: new Date(NOW).toISOString(),
});
function makeHAAudit(extra = {}) {
  return hashed('g-bank-ha-readiness-audit/v2', 'audit_sha256', {
    cluster_sha256: H('5'), cluster_epoch: 1, cluster_authority_root_sha256: H('2'), cluster_transition_count: 0, cluster_transition_head_sha256: null,
    active_voter_count: 3, quorum: 2, latest_term: 8, leader_node_id: 'NODE:A', fence_record_sha256: H('6'), fence_valid_until: new Date(NOW + 120000).toISOString(),
    latest_commit_index: 42, latest_commit_sha256: H('7'), replicated_state_root_sha256: H('3'), checkpoint_state_root_sha256: H('3'),
    voter_journal_store_count: 3, voter_journal_heads: { 'NODE:A': H('a'), 'NODE:B': H('b'), 'NODE:C': null }, voter_journal_root_sha256: H('0'),
    durable_fence_signer_count: 2, durable_commit_signer_count: 2, reasons: [], audited_at: new Date(NOW).toISOString(), grants_external_rights: false,
    permits_value_movement_by_itself: false, distributed_network_verified: false, ...extra,
  });
}
function makeDeploymentAudit(extra = {}) {
  return hashed('g-bank-ha-deployment-audit/v2', 'audit_sha256', {
    cluster_sha256: H('5'), cluster_epoch: 1, active_voter_count: 3, observed_active_voter_count: 3, observer_id: 'OBSERVER:PRIMARY',
    observer_public_key_binding_sha256: H('8'), observation_sha256: H('9'), observed_at: new Date(NOW).toISOString(), audited_at: new Date(NOW).toISOString(),
    distributed_network_verified: true, all_active_voters_healthy: true, unique_machine_identities_verified: true, unique_endpoints_verified: true,
    unique_failure_domains_verified: true, grants_external_rights: false, permits_value_movement_by_itself: false, ...extra,
  });
}
const haAudit = makeHAAudit();
const haDeploymentAudit = makeDeploymentAudit();
const transportPreflight = { environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST', settlement_system: 'TIPS', external_receipt_sha256: H('1') };
const completeEnv = {
  ...base, G_BANK_LEGAL_AUTHORIZATION_EVIDENCE_SHA256: H('c'), G_BANK_SCHEME_PARTICIPATION_EVIDENCE_SHA256: H('d'), G_BANK_SETTLEMENT_ACCESS_EVIDENCE_SHA256: H('e'),
  G_BANK_PRODUCTION_IDENTITY_EVIDENCE_SHA256: H('f'), G_BANK_PRUDENTIAL_AUDIT_SHA256: prudential.invariant_audit.audit_sha256,
  G_BANK_OPERATIONAL_RESILIENCE_SHA256: prudential.operational_resilience.assessment_sha256, G_BANK_TREASURY_ASSESSMENT_SHA256: prudential.treasury.assessment_sha256,
  G_BANK_CUSTOMER_MONITORING_AUDIT_SHA256: monitoringAudit.audit_sha256, G_BANK_RECOVERY_AUDIT_SHA256: recoveryAudit.audit_sha256,
  G_BANK_HA_AUDIT_SHA256: haAudit.audit_sha256, G_BANK_HA_DEPLOYMENT_AUDIT_SHA256: haDeploymentAudit.audit_sha256,
};
function assess(overrides = {}) {
  return assessSovereignReadiness({ env: completeEnv, governance, prudential, monitoringAudit, recoveryAudit, haAudit, haDeploymentAudit, transportPreflight, now: NOW, ...overrides });
}

const blocked = assessSovereignReadiness({ env: base, governance, prudential, monitoringAudit, recoveryAudit, haAudit, haDeploymentAudit, transportPreflight, now: NOW });
assert.equal(blocked.direct_live_ready, false);
assert.equal(blocked.state, 'DIRECT_LIVE_BLOCKED');

const ready = assess();
assert.equal(ready.direct_live_ready, true);
assert.equal(ready.ha_controls_verified, true);
assert.equal(ready.ha_deployment_verified, true);
assert.equal(ready.checks.ha_cluster_authority_root_present, true);
assert.equal(ready.checks.ha_cluster_transition_chain_consistent, true);
assert.equal(ready.checks.ha_checkpoint_matches_recovery, true);
assert.equal(ready.checks.ha_voter_journal_root_present, true);
assert.equal(ready.checks.ha_voter_journal_store_coverage_complete, true);
assert.equal(ready.checks.ha_durable_fence_quorum, true);
assert.equal(ready.checks.ha_durable_commit_quorum, true);
assert.equal(ready.checks.ha_distributed_network_verified, true);
assert.equal(ready.ha_cluster_authority_root_sha256, H('2'));

for (const [field, value, check] of [
  ['cluster_authority_root_sha256', null, 'ha_cluster_authority_root_present'],
  ['voter_journal_root_sha256', null, 'ha_voter_journal_root_present'],
  ['voter_journal_store_count', 2, 'ha_voter_journal_store_coverage_complete'],
  ['durable_fence_signer_count', 1, 'ha_durable_fence_quorum'],
  ['durable_commit_signer_count', 1, 'ha_durable_commit_quorum'],
]) {
  const weakHA = makeHAAudit({ [field]: value });
  const weakEnv = { ...completeEnv, G_BANK_HA_AUDIT_SHA256: weakHA.audit_sha256 };
  const result = assess({ env: weakEnv, haAudit: weakHA });
  assert.equal(result.direct_live_ready, false);
  assert.equal(result.checks[check], false);
}
const impossibleTransition = makeHAAudit({ cluster_transition_count: 1, cluster_transition_head_sha256: null });
const impossibleTransitionEnv = { ...completeEnv, G_BANK_HA_AUDIT_SHA256: impossibleTransition.audit_sha256 };
const impossible = assess({ env: impossibleTransitionEnv, haAudit: impossibleTransition });
assert.equal(impossible.direct_live_ready, false);
assert.equal(impossible.checks.ha_cluster_transition_chain_consistent, false);

const noDeployment = assess({ haDeploymentAudit: null });
assert.equal(noDeployment.direct_live_ready, false);
const tamperedDeployment = assess({ haDeploymentAudit: { ...haDeploymentAudit, observed_active_voter_count: 999 } });
assert.equal(tamperedDeployment.direct_live_ready, false);
const staleDeployment = makeDeploymentAudit({ observed_at: new Date(NOW - 61000).toISOString(), audited_at: new Date(NOW - 61000).toISOString() });
const staleDeploymentEnv = { ...completeEnv, G_BANK_HA_DEPLOYMENT_AUDIT_SHA256: staleDeployment.audit_sha256 };
assert.equal(assess({ env: staleDeploymentEnv, haDeploymentAudit: staleDeployment }).direct_live_ready, false);
const wrongClusterDeployment = makeDeploymentAudit({ cluster_sha256: H('a') });
const wrongClusterEnv = { ...completeEnv, G_BANK_HA_DEPLOYMENT_AUDIT_SHA256: wrongClusterDeployment.audit_sha256 };
assert.equal(assess({ env: wrongClusterEnv, haDeploymentAudit: wrongClusterDeployment }).direct_live_ready, false);

const noHA = assess({ haAudit: null });
assert.equal(noHA.direct_live_ready, false);
const tamperedHA = assess({ haAudit: { ...haAudit, latest_commit_index: 999 } });
assert.equal(tamperedHA.direct_live_ready, false);
const differentRootHA = makeHAAudit({ replicated_state_root_sha256: H('a'), checkpoint_state_root_sha256: H('a') });
const differentRootEnv = { ...completeEnv, G_BANK_HA_AUDIT_SHA256: differentRootHA.audit_sha256 };
assert.equal(assess({ env: differentRootEnv, haAudit: differentRootHA }).direct_live_ready, false);
const expiredHA = makeHAAudit({ fence_valid_until: new Date(NOW - 1).toISOString() });
const expiredEnv = { ...completeEnv, G_BANK_HA_AUDIT_SHA256: expiredHA.audit_sha256 };
assert.equal(assess({ env: expiredEnv, haAudit: expiredHA }).direct_live_ready, false);
const noRecovery = assess({ recoveryAudit: null });
assert.equal(noRecovery.direct_live_ready, false);
const noMonitoring = assess({ monitoringAudit: null });
assert.equal(noMonitoring.direct_live_ready, false);
const noPrudential = assess({ prudential: null });
assert.equal(noPrudential.direct_live_ready, false);
const weakQuorum = assess({ governance: { ...governance, high_value_quorum: 1 } });
assert.equal(weakQuorum.direct_live_ready, false);
const fake = assess({ env: { ...completeEnv, G_BANK_SIMULATED_LIVE_SUCCESS: 'true' } });
assert.equal(fake.direct_live_ready, false);

console.log('G-BANK sovereign v2 readiness tests: PASS');
