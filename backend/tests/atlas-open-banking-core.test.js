#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { normalizeIntent, routeIntent } = require('../../scripts/atlas-open-banking-core');
const { YapilyConnectAdapter, BunqNativeAdapter } = require('../../scripts/atlas-open-banking-adapters');
const { evaluateInstitution } = require('../../scripts/atlas-open-banking-capabilities');
const h = v => crypto.createHash('sha256').update(v).digest('hex');

const intent = normalizeIntent({
  intent_id: 'mercedes-294900', amount_in_minor: 29_490_000, currency: 'EUR',
  beneficiary_name: 'Dealer', beneficiary_iban_sha256: h('iban'), reference: 'CAR',
  owner_approval_sha256: h('owner'), invoice_sha256: h('invoice')
});
assert.equal(intent.amount_in_minor, 29_490_000);
assert.match(intent.intent_binding_sha256, /^[0-9a-f]{64}$/);

const bunq = new BunqNativeAdapter({ env: {
  BUNQ_API_KEY: 'secret', BUNQ_ENV: 'production', BUNQ_LIMIT_EVIDENCE_VERIFIED: 'true',
  BUNQ_DRAFT_PAYMENT_WRITE_VERIFIED: 'true', BUNQ_VERIFIED_MAX_PAYMENT_EUR: '300000'
}});
const yapily = new YapilyConnectAdapter({ env: {
  YAPILY_ENV: 'production', YAPILY_APPLICATION_KEY: 'key', YAPILY_APPLICATION_SECRET: 'secret',
  YAPILY_CONNECT_APPROVED: 'true', YAPILY_HIGH_VALUE_WAIVER_APPROVED: 'true',
  YAPILY_APPROVED_MAX_PAYMENT_EUR: '300000'
}});const routed = routeIntent({ intent, adapters: [yapily, bunq] });
assert.equal(routed.decision, 'EXECUTION_CANDIDATE');
assert.equal(routed.selected_adapter_id, 'bunq-native-draft');
assert.equal(routed.provider_call_permitted, false);
assert.equal(routed.value_moved, false);

const yapilyRequest = yapily.buildInitiationRequest({
  intent, institution_id: 'bank-nl-test', raw_beneficiary_iban: 'FR7612345678901234567890185',
  callback_url: 'https://example.test/callback'
});
assert.equal(yapilyRequest.network_request_performed, false);
assert.equal(yapilyRequest.value_moved, false);

const bunqRequest = bunq.buildInitiationRequest({
  intent, user_id: '1', monetary_account_id: '2', raw_beneficiary_iban: 'FR7612345678901234567890185'
});
assert.equal(bunqRequest.requires_user_bank_approval, true);
assert.equal(bunqRequest.network_request_performed, false);

const now = new Date();
const cap = {
  institution_id: 'bank-nl-test', provider: 'yapily', countries: ['NL'],
  schemes: ['sepa_credit_transfer'], payment_initiation: true, sca_supported: true,
  max_amount_in_minor: 30_000_000, registration_state: 'REGISTERED',
  observed_at: new Date(now.getTime() - 1000).toISOString(),
  expires_at: new Date(now.getTime() + 60000).toISOString()
};
assert.equal(evaluateInstitution({ capability: cap, amount_in_minor: 29_490_000, now }).state, 'ELIGIBLE');
console.log('atlas-open-banking-core: PASS');
