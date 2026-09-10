'use strict';

const assert = require('node:assert/strict');
const { assessSovereignReadiness } = require('../g-bank-sovereign-v2/readiness');

const H = c => c.repeat(64);

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
  safeguarding: {
    schema: 'g-bank-safeguarding-assessment/v2',
    state: 'PASS',
    assessment_sha256: H('5'),
  },
  liquidity: {
    schema: 'g-bank-liquidity-assessment/v2',
    state: 'PASS',
    assessment_sha256: H('6'),
  },
  invariant_audit: {
    schema: 'g-bank-sovereign-invariant-audit/v2',
    state: 'PASS',
    audit_sha256: H('9'),
  },
};

const blocked = assessSovereignReadiness({
  env: base,
  governance,
  prudential,
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
};
const ready = assessSovereignReadiness({
  env: completeEnv,
  governance,
  prudential,
  transportPreflight: {
    environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST',
    settlement_system: 'TIPS', external_receipt_sha256: H('1'),
  },
});
assert.equal(ready.direct_live_ready, true);
assert.equal(ready.external_transport_verified, true);
assert.equal(ready.prudential_controls_verified, true);
assert.equal(ready.checks.high_value_quorum_dual_control, true);
assert.equal(ready.checks.prudential_audit_binding_matches, true);

const noPrudential = assessSovereignReadiness({
  env: completeEnv,
  governance,
  prudential: null,
  transportPreflight: {
    environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST',
    settlement_system: 'TIPS', external_receipt_sha256: H('2'),
  },
});
assert.equal(noPrudential.direct_live_ready, false);
assert.equal(noPrudential.prudential_controls_verified, false);
assert.equal(noPrudential.checks.safeguarding_pass, false);

const failedSafeguarding = assessSovereignReadiness({
  env: completeEnv,
  governance,
  prudential: {
    ...prudential,
    safeguarding: { ...prudential.safeguarding, state: 'BLOCK' },
  },
  transportPreflight: {
    environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST',
    settlement_system: 'TIPS', external_receipt_sha256: H('2'),
  },
});
assert.equal(failedSafeguarding.direct_live_ready, false);
assert.equal(failedSafeguarding.checks.safeguarding_pass, false);

const noGovernance = assessSovereignReadiness({
  env: completeEnv,
  governance: null,
  prudential,
  transportPreflight: {
    environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST',
    settlement_system: 'TIPS', external_receipt_sha256: H('2'),
  },
});
assert.equal(noGovernance.direct_live_ready, false);
assert.equal(noGovernance.checks.risk_policy_binding_present, false);

const weakQuorum = assessSovereignReadiness({
  env: completeEnv,
  governance: { ...governance, high_value_quorum: 1 },
  prudential,
  transportPreflight: {
    environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST',
    settlement_system: 'TIPS', external_receipt_sha256: H('3'),
  },
});
assert.equal(weakQuorum.direct_live_ready, false);
assert.equal(weakQuorum.checks.high_value_quorum_dual_control, false);

const fake = assessSovereignReadiness({
  env: { ...completeEnv, G_BANK_SIMULATED_LIVE_SUCCESS: 'true' },
  governance,
  prudential,
  transportPreflight: {
    environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST',
    settlement_system: 'TIPS', external_receipt_sha256: H('4'),
  },
});
assert.equal(fake.direct_live_ready, false);
assert.equal(fake.checks.simulated_live_success_forbidden, false);

console.log('G-BANK sovereign v2 readiness tests: PASS');
