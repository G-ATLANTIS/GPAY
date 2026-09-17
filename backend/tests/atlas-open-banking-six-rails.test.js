#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { normalizeIntent, routeIntent } = require('../../scripts/atlas-open-banking-core');
const {
  AdyenOutboundAdapter,
  TinkOpenBankingAdapter,
  DirectSepaAdapter,
  buildDefaultAdapters
} = require('../../scripts/atlas-open-banking-adapters');

const h = v => crypto.createHash('sha256').update(v).digest('hex');

const registryIds = buildDefaultAdapters({ env: {} }).map(x => x.id);
assert.deepEqual(registryIds, [
  'bunq-native-draft', 'atlas-direct-sepa', 'atlas-own-pisp',
  'adyen-api', 'yapily-connect', 'tink-open-banking'
]);

const intent = normalizeIntent({
  intent_id: 'mercedes-294900-six-rails', amount_in_minor: 29_490_000, currency: 'EUR',
  beneficiary_name: 'Verified Dealer Placeholder', beneficiary_iban_sha256: h('iban'), reference: 'CAR',
  owner_approval_sha256: h('owner'), invoice_sha256: h('invoice')
});

for (const adapter of [
  new AdyenOutboundAdapter({ env: {} }),
  new TinkOpenBankingAdapter({ env: {} }),
  new DirectSepaAdapter({ env: {} })
]) {
  const result = routeIntent({ intent, adapters: [adapter] });
  assert.equal(result.decision, 'BLOCKED');
  assert.equal(result.provider_call_permitted, false);
  assert.equal(result.value_moved, false);
  assert.ok(result.evaluated[0].blockers.length > 0);
}

const adyen = new AdyenOutboundAdapter({ env: {
  ADYEN_ENV: 'production', ADYEN_API_KEY: 'test-key', ADYEN_MERCHANT_ACCOUNT: 'test-merchant',
  ADYEN_OUTBOUND_PAYMENTS_APPROVED: 'true', ADYEN_LIMIT_EVIDENCE_VERIFIED: 'true',
  ADYEN_CALLBACK_VERIFIED: 'true', ADYEN_READBACK_VERIFIED: 'true',
  ADYEN_VERIFIED_MAX_PAYMENT_EUR: '300000'
}});
const tink = new TinkOpenBankingAdapter({ env: {
  TINK_ENV: 'production', TINK_CLIENT_ID: 'test-id', TINK_CLIENT_SECRET: 'test-secret',
  TINK_PRODUCTION_ONBOARDING_VERIFIED: 'true', TINK_PISP_VERIFIED: 'true',
  TINK_LIMIT_EVIDENCE_VERIFIED: 'true', TINK_CALLBACK_VERIFIED: 'true', TINK_READBACK_VERIFIED: 'true',
  TINK_VERIFIED_MAX_PAYMENT_EUR: '300000'
}});
const sepa = new DirectSepaAdapter({ env: {
  ATLAS_DIRECT_SEPA_PRODUCTION: 'true', ATLAS_DIRECT_SEPA_PSP_AUTHORIZATION_VERIFIED: 'true',
  ATLAS_DIRECT_SEPA_NETWORK_ACCESS_VERIFIED: 'true', ATLAS_DIRECT_SEPA_SETTLEMENT_ACCESS_VERIFIED: 'true',
  ATLAS_DIRECT_SEPA_SCA_VERIFIED: 'true', ATLAS_DIRECT_SEPA_LIMIT_EVIDENCE_VERIFIED: 'true',
  ATLAS_DIRECT_SEPA_VERIFIED_MAX_PAYMENT_EUR: '300000'
}});

for (const adapter of [adyen, tink, sepa]) {
  const result = routeIntent({ intent, adapters: [adapter] });
  assert.equal(result.decision, 'EXECUTION_CANDIDATE');
  assert.equal(result.selected_adapter_id, adapter.id);
  assert.equal(result.provider_call_permitted, false);
  assert.equal(result.value_moved, false);
}

const adyenReq = adyen.buildInitiationRequest({ intent, raw_beneficiary_iban: 'FR7612345678901234567890185' });
const tinkReq = tink.buildInitiationRequest({ intent, institution_id: 'bank-fr-test', raw_beneficiary_iban: 'FR7612345678901234567890185', callback_url: 'https://example.test/callback' });
const sepaReq = sepa.buildInitiationRequest({ intent, raw_beneficiary_iban: 'FR7612345678901234567890185', scheme: 'SCT' });
for (const req of [adyenReq, tinkReq, sepaReq]) {
  assert.equal(req.network_request_performed, false);
  assert.equal(req.value_moved, false);
}
assert.equal(sepaReq.requires_explicit_owner_authorization, true);
console.log('atlas-open-banking-six-rails: PASS');
