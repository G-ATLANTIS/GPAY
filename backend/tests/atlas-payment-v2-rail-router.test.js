#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const { evaluateRail } = require('../../scripts/atlas-payment-v2-rail-router');

const highValue = evaluateRail({
  amount_in_minor: 29490000,
  currency: 'EUR',
  provider_entitlement_verified: true,
  provider_id_verified: true,
  beneficiary_verified: true,
  bank_limit_verified: true,
  max_amount_in_minor: 30000000,
  provider_supports_sepa_credit: true,
  provider_supports_instant: false,
  new_sca_required: true
});
assert.equal(highValue.state, 'ELIGIBLE_REQUIRES_SCA');
assert.equal(highValue.scheme_selection, 'SEPA_CREDIT');
assert.equal(highValue.execution_candidate, true);
assert.equal(highValue.sca_required, true);
assert.deepEqual(highValue.blockers, []);
const unknownSca = evaluateRail({
  amount_in_minor: 29490000,
  currency: 'EUR',
  provider_entitlement_verified: true,
  provider_id_verified: true,
  beneficiary_verified: true,
  bank_limit_verified: true,
  max_amount_in_minor: 30000000,
  provider_supports_sepa_credit: true
});
assert.equal(unknownSca.state, 'BLOCKED');
assert(unknownSca.blockers.includes('SCA_REQUIREMENT_UNKNOWN'));

const missingProvider = evaluateRail({
  amount_in_minor: 29490000,
  currency: 'EUR',
  provider_entitlement_verified: true,
  provider_id_verified: false,
  beneficiary_verified: true,
  bank_limit_verified: true,
  max_amount_in_minor: 30000000,
  provider_supports_sepa_credit: true,
  new_sca_required: true
});
assert.equal(missingProvider.state, 'BLOCKED');
assert(missingProvider.blockers.includes('PROVIDER_ID_REQUIRED'));

console.log('atlas-payment-v2-rail-router: PASS');
