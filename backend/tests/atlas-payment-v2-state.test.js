#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { initialState, transition } = require('../../scripts/atlas-payment-v2-state');
const h = value => crypto.createHash('sha256').update(value).digest('hex');

let s = initialState({ intent_id: 'intent-294900', amount_in_minor: 29_490_000 });
s = transition(s, 'OWNER_APPROVED', { owner_approval_sha256: h('owner') });
s = transition(s, 'PROVIDER_ENTITLEMENT_VERIFIED', { provider_entitlement_sha256: h('provider') });
s = transition(s, 'BENEFICIARY_VERIFIED', { beneficiary_verification_sha256: h('beneficiary') });
s = transition(s, 'BANK_AND_AMOUNT_ELIGIBLE', { bank_eligibility_sha256: h('bank') });
s = transition(s, 'PAYMENT_CREATED_AWAITING_SCA', {
  provider_create_receipt_sha256: h('create'),
  payment_id: 'pay-test-001'
});
assert.equal(s.value_moved, false);
s = transition(s, 'USER_SCA_AUTHORIZED', { sca_authorization_sha256: h('sca') });
s = transition(s, 'PROVIDER_SUBMITTED', { provider_submission_sha256: h('submit') });
s = transition(s, 'SETTLED', {
  settlement_receipt_sha256: h('settled'),
  amount_in_minor: 29_490_000,
  currency: 'EUR'
});
assert.equal(s.value_moved, true);s = transition(s, 'RECONCILED', { reconciliation_receipt_sha256: h('reconciled') });
assert.equal(s.state, 'RECONCILED');
assert.equal(s.reconciled, true);

assert.throws(() => transition(
  initialState({ intent_id: 'x', amount_in_minor: 100 }),
  'SETTLED',
  { settlement_receipt_sha256: h('x'), amount_in_minor: 100, currency: 'EUR' }
), /invalid_transition/);

let mismatch = initialState({ intent_id: 'm', amount_in_minor: 100 });
mismatch = transition(mismatch, 'OWNER_APPROVED', { owner_approval_sha256: h('1') });
mismatch = transition(mismatch, 'PROVIDER_ENTITLEMENT_VERIFIED', { provider_entitlement_sha256: h('2') });
mismatch = transition(mismatch, 'BENEFICIARY_VERIFIED', { beneficiary_verification_sha256: h('3') });
mismatch = transition(mismatch, 'BANK_AND_AMOUNT_ELIGIBLE', { bank_eligibility_sha256: h('4') });
mismatch = transition(mismatch, 'PAYMENT_CREATED_AWAITING_SCA', { provider_create_receipt_sha256: h('5'), payment_id: 'p' });
mismatch = transition(mismatch, 'USER_SCA_AUTHORIZED', { sca_authorization_sha256: h('6') });
mismatch = transition(mismatch, 'PROVIDER_SUBMITTED', { provider_submission_sha256: h('7') });
assert.throws(() => transition(mismatch, 'SETTLED', {
  settlement_receipt_sha256: h('8'), amount_in_minor: 99, currency: 'EUR'
}), /settlement_amount_mismatch/);

console.log('atlas-payment-v2-state: PASS');
