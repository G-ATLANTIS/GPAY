#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const { combineReports } = require('../../scripts/atlas-payment-v2-audit');

const ready = combineReports({
  state: 'READY_TO_CREATE_PAYMENT',
  amount_eur: 294900,
  amount_in_minor: 29_490_000,
  scheme_selection: 'SEPA_CREDIT',
  blockers: [],
  provider_oauth_error: null,
  configured_max_payment_eur: 300000
}, {
  state: 'READY',
  blockers: [],
  webhook_http_status: 200,
  return_http_status: 200,
  webhook_environment: 'live'
});
assert.equal(ready.state, 'READY_FOR_PAYMENT_CREATE');
assert.deepEqual(ready.blockers, []);
const blocked = combineReports({
  state: 'BLOCKED',
  amount_eur: 294900,
  amount_in_minor: 29_490_000,
  scheme_selection: 'SEPA_CREDIT',
  blockers: ['PROVIDER_ENTITLEMENT_REQUIRED'],
  provider_oauth_error: 'invalid_scope',
  configured_max_payment_eur: 100
}, {
  state: 'BLOCKED',
  blockers: ['PUBLIC_RETURN_URI_UNREACHABLE'],
  webhook_http_status: 200,
  return_http_status: 404,
  webhook_environment: 'sandbox'
});
assert.equal(blocked.state, 'BLOCKED');
assert(blocked.blockers.includes('PROVIDER_ENTITLEMENT_REQUIRED'));
assert(blocked.blockers.includes('PUBLIC_RETURN_URI_UNREACHABLE'));
assert.equal(blocked.payment_endpoint_called, false);
assert.equal(blocked.value_moved, false);

console.log('atlas-payment-v2-audit: PASS');
