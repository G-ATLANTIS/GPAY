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
  G_BANK_OPERATIONAL_RESILIENCE_SHA256: prudential.operational_resilience.assessment_sha256,
  G_BANK_TREASURY_ASSESSMENT_SHA256: prudential.treasury.assessment_sha256,
};
const transportPreflight = {
  environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST',
  settlement_system: 'TIPS', external_receipt_sha256: H('1'),
};

const ready = assessSovereignReadiness({ env: completeEnv, governance, prudential, transportPreflight });
assert.equal(ready.direct_live_ready, true);
assert.equal(ready.external_transport_verified, true);
assert.equal(ready.prudential_controls_verified, true);
assert.equal(ready.operational_controls_verified, true);
assert.equal(ready.checks.high_value_quorum_dual_control, true);
assert.equal(ready.checks.prudential_audit_binding_matches, true);
assert.equal(ready.checks.operational_resilience_binding_matches, true);
assert.equal(ready.checks.treasury_binding_matches, true);
assert.equal(ready.checks.treasury_pass, true);

const noPrudential = assessSovereignReadiness({ env: completeEnv, governance, prudential: null, transportPreflight });
assert.equal(noPrudential.direct_live_ready, false);
assert.equal(noPrudential.prudential_controls_verified, false);
assert.equal(noPrudential.operational_controls_verified, false);
assert.equal(noPrudential.checks.safeguarding_pass, false);
assert.equal(noPrudential.checks.treasury_pass, false);

const failedSafeguarding = assessSovereignReadiness({
  env: completeEnv,
  governance,
  prudential: { ...prudential, safeguarding: { ...prudential.safeguarding, state: 'BLOCK' } },
  transportPreflight,
});
assert.equal(failedSafeguarding.direct_live_ready, false);
assert.equal(failedSafeguarding.checks.safeguarding_pass, false);

const failedTreasury = assessSovereignReadiness({
  env: completeEnv,
  governance,
  prudential: { ...prudential, treasury: { ...prudential.treasury, state: 'BLOCK' } },
  transportPreflight,
});
assert.equal(failedTreasury.direct_live_ready, false);
assert.equal(failedTreasury.checks.treasury_pass, false);

const tamperedTreasury = assessSovereignReadiness({
  env: completeEnv,
  governance,
  prudential: { ...prudential, treasury: { ...prudential.treasury, settlement_headroom_minor: 999999 } },
  transportPreflight,
});
assert.equal(tamperedTreasury.direct_live_ready, false);
assert.equal(tamperedTreasury.checks.treasury_pass, false);

const frozen = assessSovereignReadiness({
  env: completeEnv,
  governance,
  prudential: { ...prudential, operational_resilience: { ...prudential.operational_resilience, state: 'BLOCK' } },
  transportPreflight,
});
assert.equal(frozen.direct_live_ready, false);
assert.equal(frozen.operational_controls_verified, false);
assert.equal(frozen.checks.operational_resilience_pass, false);

const noGovernance = assessSovereignReadiness({ env: completeEnv, governance: null, prudential, transportPreflight });
assert.equal(noGovernance.direct_live_ready, false);
assert.equal(noGovernance.checks.risk_policy_binding_present, false);

const weakQuorum = assessSovereignReadiness({
  env: completeEnv,
  governance: { ...governance, high_value_quorum: 1 },
  prudential,
  transportPreflight,
});
assert.equal(weakQuorum.direct_live_ready, false);
assert.equal(weakQuorum.checks.high_value_quorum_dual_control, false);

const fake = assessSovereignReadiness({
  env: { ...completeEnv, G_BANK_SIMULATED_LIVE_SUCCESS: 'true' },
  governance,
  prudential,
  transportPreflight,
});
assert.equal(fake.direct_live_ready, false);
assert.equal(fake.checks.simulated_live_success_forbidden, false);

console.log('G-BANK sovereign v2 readiness tests: PASS');
