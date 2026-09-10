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
  G_BANK_SETTLEMENT_TRANSPORT_MODULE: '/authorized/transport.js',
  G_BANK_SETTLEMENT_AUTHORIZATION_SHA256: H('a'),
};

const blocked = assessSovereignReadiness({
  env: base,
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
};
const ready = assessSovereignReadiness({
  env: completeEnv,
  transportPreflight: {
    environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST',
    settlement_system: 'TIPS', external_receipt_sha256: H('1'),
  },
});
assert.equal(ready.direct_live_ready, true);
assert.equal(ready.external_transport_verified, true);

const fake = assessSovereignReadiness({
  env: { ...completeEnv, G_BANK_SIMULATED_LIVE_SUCCESS: 'true' },
  transportPreflight: {
    environment: 'LIVE', authenticated: true, connected: true, scheme: 'SCT_INST',
    settlement_system: 'TIPS', external_receipt_sha256: H('2'),
  },
});
assert.equal(fake.direct_live_ready, false);
assert.equal(fake.checks.simulated_live_success_forbidden, false);

console.log('G-BANK sovereign v2 readiness tests: PASS');
