#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const {
  buildPaymentPayload
} = require('../../scripts/atlas-payment-v2-provider');

const payload = buildPaymentPayload({
  intent_id: 'test-intent-001',
  amount_in_minor: 29_490_000,
  currency: 'EUR',
  provider_id: 'mock-payments-fr-redirect',
  beneficiary_name: 'TEST DEALER',
  beneficiary_iban: 'FR5217569000506231212211X69',
  reference: 'CAR-TEST-001',
  user_name: 'Test Buyer',
  user_email: 'buyer@example.com',
  country_code: 'NL',
  language_code: 'nl',
  return_uri: 'https://bank.gijs.live/api/open-banking/return'
});

assert.equal(payload.amount_in_minor, 29_490_000);
assert.equal(payload.payment_method.beneficiary.type, 'external_account');
assert.equal(payload.payment_method.provider_selection.type, 'preselected');
assert.equal(payload.payment_method.provider_selection.scheme_selection.type, 'preselected');
assert.equal(payload.payment_method.provider_selection.scheme_selection.scheme_id, 'sepa_credit_transfer');assert.equal(payload.hosted_page.return_uri, 'https://bank.gijs.live/api/open-banking/return');
assert.equal(payload.user.name, 'Test Buyer');

assert.throws(() => buildPaymentPayload({
  intent_id: 'x',
  amount_in_minor: 29_490_000,
  currency: 'EUR',
  beneficiary_name: 'TEST DEALER',
  beneficiary_iban: 'FR5217569000506231212211X69',
  reference: 'CAR-TEST-001',
  user_name: 'Test Buyer',
  user_email: 'buyer@example.com',
  country_code: 'NL',
  return_uri: 'https://bank.gijs.live/api/open-banking/return'
}), /provider_id_required/);

assert.throws(() => buildPaymentPayload({
  intent_id: 'x', amount_in_minor: 100, currency: 'EUR',
  beneficiary_name: 'TEST', beneficiary_iban: 'FR5217569000506231212211X69',
  reference: 'TEST', user_name: 'Test Buyer', user_email: 'buyer@example.com',
  return_uri: 'http://unsafe.example.com'
}), /return_uri_invalid/);

console.log('atlas-payment-v2-provider: PASS');
