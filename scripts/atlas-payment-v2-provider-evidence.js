#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');

const PAYMENT_STATUSES = new Set([
  'authorization_required',
  'authorizing',
  'authorized',
  'executed',
  'failed'
]);


const ALLOWED_EUR_SCHEMES = new Set([
  'sepa_credit_transfer',
  'sepa_credit_transfer_instant'
]);

function verifyExecutedScheme(paymentMethod) {
  const schemeId = String(paymentMethod?.scheme_id || '').trim();
  if (!schemeId) throw new Error('provider_scheme_id_missing');
  if (!ALLOWED_EUR_SCHEMES.has(schemeId)) throw new Error('provider_scheme_not_allowed');
  return schemeId;
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value ?? '')).digest('hex');
}

function uuid(value, field) {
  const text = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(text)) {
    throw new Error(`${field}_invalid`);
  }
  return text;
}

function exactMoney(resource, amount, currency) {
  if (resource.amount_in_minor !== amount) throw new Error('provider_amount_mismatch');
  if (String(resource.currency || '').toUpperCase() !== currency) {
    throw new Error('provider_currency_mismatch');
  }
}
function verifyCreateResponse({ response, expected_amount_in_minor, expected_currency = 'EUR' }) {
  if (!response || typeof response !== 'object') throw new Error('create_response_invalid');
  const paymentId = uuid(response.id, 'payment_id');
  if (response.status !== 'authorization_required') {
    throw new Error('create_response_status_invalid');
  }
  const amount = Number(expected_amount_in_minor);
  if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('expected_amount_invalid');

  if ('amount_in_minor' in response || 'currency' in response) {
    exactMoney(response, amount, String(expected_currency).toUpperCase());
  }

  const hostedUri = String(response.hosted_page?.uri || '');
  if (hostedUri) {
    const parsed = new URL(hostedUri);
    if (parsed.protocol !== 'https:' || !parsed.hostname.endsWith('truelayer.com')) {
      throw new Error('hosted_page_uri_invalid');
    }
  }

  const receipt = {
    schema: 'atlas-payment-create-receipt-v2',
    payment_id: paymentId,
    status: response.status,
    hosted_page_uri_present: Boolean(hostedUri),
    resource_token_present: typeof response.resource_token === 'string' && response.resource_token.length > 0,
    amount_in_minor: amount,
    currency: String(expected_currency).toUpperCase(),
    payment_created: true,
    value_moved: false
  };
  receipt.receipt_sha256 = sha256(JSON.stringify(receipt));
  return receipt;
}
function verifyStatusResource({ resource, expected_payment_id, expected_amount_in_minor, expected_currency = 'EUR' }) {
  if (!resource || typeof resource !== 'object') throw new Error('payment_resource_invalid');
  const paymentId = uuid(resource.id, 'payment_id');
  if (paymentId !== uuid(expected_payment_id, 'expected_payment_id')) {
    throw new Error('payment_id_mismatch');
  }
  if (!PAYMENT_STATUSES.has(resource.status)) throw new Error('payment_status_unknown');
  exactMoney(resource, Number(expected_amount_in_minor), String(expected_currency).toUpperCase());
  const schemeId = resource.status === 'executed'
    ? verifyExecutedScheme(resource.payment_method)
    : null;

  const receipt = {
    schema: 'atlas-payment-status-receipt-v2',
    payment_id: paymentId,
    status: resource.status,
    amount_in_minor: resource.amount_in_minor,
    currency: String(resource.currency).toUpperCase(),
    provider_execution_verified: resource.status === 'executed',
    scheme_id: schemeId,
    creditor_settlement_confirmed: false,
    failed: resource.status === 'failed',
    value_moved: false
  };
  receipt.receipt_sha256 = sha256(JSON.stringify(receipt));
  return receipt;
}

function verifyWebhook({ event, expected_payment_id, signature_verified }) {
  if (signature_verified !== true) throw new Error('webhook_signature_not_verified');
  if (!event || typeof event !== 'object') throw new Error('webhook_invalid');
  const paymentId = uuid(event.payment_id, 'payment_id');
  if (paymentId !== uuid(expected_payment_id, 'expected_payment_id')) {
    throw new Error('webhook_payment_id_mismatch');
  }
  uuid(event.event_id, 'event_id');
  const allowed = new Set(['payment_authorized', 'payment_executed', 'payment_failed']);
  if (!allowed.has(event.type)) throw new Error('webhook_type_not_allowed_for_external_payment');
  const schemeId = event.type === 'payment_executed'
    ? verifyExecutedScheme(event.payment_method)
    : null;

  const receipt = {
    schema: 'atlas-payment-webhook-receipt-v2',
    event_id: String(event.event_id).toLowerCase(),
    payment_id: paymentId,
    type: event.type,
    signature_verified: true,
    provider_execution_verified: event.type === 'payment_executed',
    scheme_id: schemeId,
    failed: event.type === 'payment_failed',
    creditor_settlement_confirmed: false,
    value_moved: false
  };
  receipt.receipt_sha256 = sha256(JSON.stringify(receipt));
  return receipt;
}

module.exports = {
  PAYMENT_STATUSES,
  ALLOWED_EUR_SCHEMES,
  verifyExecutedScheme,
  verifyCreateResponse,
  verifyStatusResource,
  verifyWebhook
};
