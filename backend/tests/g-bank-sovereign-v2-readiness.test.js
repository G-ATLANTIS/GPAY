'use strict';

const assert = require('node:assert/strict');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { assessSovereignReadiness } = require('../g-bank-sovereign-v2/readiness');

const H = c => c.repeat(64);

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
  policy_sha256: H('4'),
  policy_epoch: 2,
  monitorable_customer_count: 3,
  assessment_count: 3,
  clear_customer_count: 2,
  review_required_customer_count: 1,
  suspended_customer_count: 0,
  reasons: [],
  audited_at: '2026-09-10T08:50:00.000Z',
  regulatory_determination_made: false,
  external_report_submitted: false,
  permits_value_movement_by_itself: false,
});

const recoveryAudit = hashed('g-bank-recovery-readiness-audit/v2', 'audit_sha256', {
  generation: 7,
  manifest_sha256: H('9'),
  recovery_anchor_head_sha256: H('1'),
  recovery_anchor_record_sha256: H('2'),
  checkpoint_state_root_sha256: H('3'),
  restore_verification_sha256: H('4'),
  max_age_ms: 900000,
  checks: { synthetic_recovery_snapshot: true },
  grants_external_rights: false,
  activates_live_execution: false,
  permits_value_movement: false,
  audited_at: '2026-09-10T08:50:00.000Z',
});

const blocked = assessSovereignReadiness({
  env: base,
  governance,
  prudential,
  monitoringAudit,
  recoveryAudit,
  transportPreflight: {
    environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST',
    settlement_system: 'TIPS', external_receipt_sha256: H('b'),
  },
});
assert.equal(blocked.direct_live_ready, false);
assert.equal(blocked.state, 'DIRECT_LIVE_BLOCKED');
assert.equal(blocked.checks.legal_authorization_evidence_binding_present, false);

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
};
const transportPreflight = {
  environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST',
  settlement_system: 'TIPS', external_receipt_sha256: H('1'),
};

const ready = assessSovereignReadiness({ env: completeEnv, governance, prudential, monitoringAudit, recoveryAudit, transportPreflight });
assert.equal(ready.direct_live_ready, true);
assert.equal(ready.external_transport_verified, true);
assert.equal(ready.prudential_controls_verified, true);
assert.equal(ready.operational_controls_verified, true);
assert.equal(ready.customer_monitoring_verified, true);
assert.equal(ready.recovery_controls_verified, true);
assert.equal(ready.checks.high_value_quorum_dual_control, true);
assert.equal(ready.checks.prudential_audit_binding_matches, true);
assert.equal(ready.checks.operational_resilience_binding_matches, true);
assert.equal(ready.checks.treasury_binding_matches, true);
assert.equal(ready.checks.customer_monitoring_binding_matches, true);
assert.equal(ready.checks.recovery_audit_binding_matches, true);
assert.equal(ready.checks.recovery_no_external_rights, true);
assert.equal(ready.checks.recovery_no_live_activation, true);
assert.equal(ready.checks.recovery_no_value_movement, true);

const noRecovery = assessSovereignReadiness({ env: completeEnv, governance, prudential, monitoringAudit, recoveryAudit: null, transportPreflight });
assert.equal(noRecovery.direct_live_ready, false);
assert.equal(noRecovery.recovery_controls_verified, false);
assert.equal(noRecovery.checks.recovery_audit_pass, false);

const tamperedRecovery = assessSovereignReadiness({
  env: completeEnv,
  governance,
  prudential,
  monitoringAudit,
  recoveryAudit: { ...recoveryAudit, generation: 999 },
  transportPreflight,
});
assert.equal(tamperedRecovery.direct_live_ready, false);
assert.equal(tamperedRecovery.checks.recovery_audit_pass, false);

const unsafeRecovery = hashed('g-bank-recovery-readiness-audit/v2', 'audit_sha256', {
  generation: 7,
  manifest_sha256: H('9'),
  grants_external_rights: true,
  activates_live_execution: false,
  permits_value_movement: false,
});
const unsafeRecoveryEnv = { ...completeEnv, G_BANK_RECOVERY_AUDIT_SHA256: unsafeRecovery.audit_sha256 };
const unsafeRecoveryReady = assessSovereignReadiness({ env: unsafeRecoveryEnv, governance, prudential, monitoringAudit, recoveryAudit: unsafeRecovery, transportPreflight });
assert.equal(unsafeRecoveryReady.direct_live_ready, false);
assert.equal(unsafeRecoveryReady.checks.recovery_no_external_rights, false);

const noMonitoring = assessSovereignReadiness({ env: completeEnv, governance, prudential, monitoringAudit: null, recoveryAudit, transportPreflight });
assert.equal(noMonitoring.direct_live_ready, false);
assert.equal(noMonitoring.customer_monitoring_verified, false);
assert.equal(noMonitoring.checks.customer_monitoring_pass, false);

const tamperedMonitoring = assessSovereignReadiness({
  env: completeEnv,
  governance,
  prudential,
  monitoringAudit: { ...monitoringAudit, assessment_count: 999 },
  recoveryAudit,
  transportPreflight,
});
assert.equal(tamperedMonitoring.direct_live_ready, false);
assert.equal(tamperedMonitoring.checks.customer_monitoring_pass, false);

const noPrudential = assessSovereignReadiness({ env: completeEnv, governance, prudential: null, monitoringAudit, recoveryAudit, transportPreflight });
assert.equal(noPrudential.direct_live_ready, false);
assert.equal(noPrudential.prudential_controls_verified, false);
assert.equal(noPrudential.operational_controls_verified, false);
assert.equal(noPrudential.checks.safeguarding_pass, false);
assert.equal(noPrudential.checks.treasury_pass, false);

const failedSafeguarding = assessSovereignReadiness({
  env: completeEnv,
  governance,
  prudential: { ...prudential, safeguarding: { ...prudential.safeguarding, state: 'BLOCK' } },
  monitoringAudit,
  recoveryAudit,
  transportPreflight,
});
assert.equal(failedSafeguarding.direct_live_ready, false);
assert.equal(failedSafeguarding.checks.safeguarding_pass, false);

const failedTreasury = assessSovereignReadiness({
  env: completeEnv,
  governance,
  prudential: { ...prudential, treasury: { ...prudential.treasury, state: 'BLOCK' } },
  monitoringAudit,
  recoveryAudit,
  transportPreflight,
});
assert.equal(failedTreasury.direct_live_ready, false);
assert.equal(failedTreasury.checks.treasury_pass, false);

const frozen = assessSovereignReadiness({
  env: completeEnv,
  governance,
  prudential: { ...prudential, operational_resilience: { ...prudential.operational_resilience, state: 'BLOCK' } },
  monitoringAudit,
  recoveryAudit,
  transportPreflight,
});
assert.equal(frozen.direct_live_ready, false);
assert.equal(frozen.operational_controls_verified, false);
assert.equal(frozen.checks.operational_resilience_pass, false);

const noGovernance = assessSovereignReadiness({ env: completeEnv, governance: null, prudential, monitoringAudit, recoveryAudit, transportPreflight });
assert.equal(noGovernance.direct_live_ready, false);
assert.equal(noGovernance.checks.risk_policy_binding_present, false);

const weakQuorum = assessSovereignReadiness({
  env: completeEnv,
  governance: { ...governance, high_value_quorum: 1 },
  prudential,
  monitoringAudit,
  recoveryAudit,
  transportPreflight,
});
assert.equal(weakQuorum.direct_live_ready, false);
assert.equal(weakQuorum.checks.high_value_quorum_dual_control, false);

const fake = assessSovereignReadiness({
  env: { ...completeEnv, G_BANK_SIMULATED_LIVE_SUCCESS: 'true' },
  governance,
  prudential,
  monitoringAudit,
  recoveryAudit,
  transportPreflight,
});
assert.equal(fake.direct_live_ready, false);
assert.equal(fake.checks.simulated_live_success_forbidden, false);

console.log('G-BANK sovereign v2 readiness tests: PASS');
