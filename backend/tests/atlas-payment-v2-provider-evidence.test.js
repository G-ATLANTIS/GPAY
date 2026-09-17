#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const {
  verifyCreateResponse,
  verifyStatusResource,
  verifyWebhook
} = require('../../scripts/atlas-payment-v2-provider-evidence');

const paymentId = '0afd1f6a-f611-48ce-9488-321129bb3a70';
const eventId = 'b8d4dda0-ff2c-4d77-a6da-4615e4bad941';
const amount = 29_490_000;

const created = verifyCreateResponse({
  response: {
    id: paymentId,
    status: 'authorization_required',
    hosted_page: { uri: 'https://payment.truelayer.com/pay/test' },
    resource_token: 'redacted-token-not-persisted'
  },
  expected_amount_in_minor: amount,
  expected_currency: 'EUR'
});
assert.equal(created.payment_created, true);
assert.equal(created.value_moved, false);
const executed = verifyStatusResource({
  resource: {
    id: paymentId,
    status: 'executed',
    payment_method: { scheme_id: 'sepa_credit_transfer' },
    amount_in_minor: amount,
    currency: 'EUR'
  },
  expected_payment_id: paymentId,
  expected_amount_in_minor: amount,
  expected_currency: 'EUR'
});
assert.equal(executed.provider_execution_verified, true);
assert.equal(executed.creditor_settlement_confirmed, false);
assert.equal(executed.value_moved, false);

const webhook = verifyWebhook({
  event: {
    type: 'payment_executed',
    event_id: eventId,
    payment_id: paymentId,
    payment_method: { scheme_id: 'sepa_credit_transfer' }
  },
  expected_payment_id: paymentId,
  signature_verified: true
});
assert.equal(webhook.provider_execution_verified, true);
assert.equal(webhook.value_moved, false);
assert.throws(() => verifyWebhook({
  event: {
    type: 'payment_executed',
    event_id: eventId,
    payment_id: paymentId,
    payment_method: { scheme_id: 'sepa_credit_transfer' }
  },
  expected_payment_id: paymentId,
  signature_verified: false
}), /webhook_signature_not_verified/);

assert.throws(() => verifyStatusResource({
  resource: {
    id: paymentId,
    status: 'executed',
    payment_method: { scheme_id: 'sepa_credit_transfer' },
    amount_in_minor: amount - 1,
    currency: 'EUR'
  },
  expected_payment_id: paymentId,
  expected_amount_in_minor: amount,
  expected_currency: 'EUR'
}), /provider_amount_mismatch/);

console.log('atlas-payment-v2-provider-evidence: PASS');
