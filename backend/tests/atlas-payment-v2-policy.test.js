#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const {
  schemeForEur,
  evaluatePreExecution
} = require('../../scripts/atlas-payment-v2-policy');

const green = {
  amount_in_minor: 29_490_000,
  currency: 'EUR',
  owner_approved: true,
  provider_entitlement_verified: true,
  beneficiary_verified: true,
  bank_limit_verified: true,
  bank_limit_minor: 30_000_000,
  signing_ready: true,
  idempotency_bound: true,
  sca_capable: true,
  provider_id_verified: true,
  provider_supports_sepa_credit: true,
  live_gate_enabled: true
};

assert.equal(schemeForEur(29_490_000), 'SEPA_CREDIT');
assert.equal(schemeForEur(9_999_999), 'INSTANT_PREFERRED');

const ready = evaluatePreExecution(green);
assert.equal(ready.state, 'READY_TO_CREATE_PAYMENT');
assert.equal(ready.scheme_selection, 'SEPA_CREDIT');assert.equal(ready.sca_required, true);
assert.equal(ready.payment_created, false);
assert.equal(ready.value_moved, false);

const noEntitlement = evaluatePreExecution({
  ...green,
  provider_entitlement_verified: false
});
assert.equal(noEntitlement.state, 'BLOCKED');
assert(noEntitlement.blockers.includes('PROVIDER_ENTITLEMENT_REQUIRED'));

const lowLimit = evaluatePreExecution({
  ...green,
  bank_limit_minor: 20_000_000
});
assert.equal(lowLimit.state, 'BLOCKED');
assert(lowLimit.blockers.includes('BANK_LIMIT_INSUFFICIENT'));

const liveOff = evaluatePreExecution({
  ...green,
  live_gate_enabled: false
});
assert.equal(liveOff.state, 'BLOCKED');
assert(liveOff.blockers.includes('LIVE_GATE_DISABLED'));

console.log('atlas-payment-v2-policy: PASS');
