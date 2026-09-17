#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');

const ALLOWED_SOURCES = new Set([
  'CREDITOR_BANK_CONFIRMATION',
  'CREDITOR_SIGNED_RECEIPT',
  'INDEPENDENT_SETTLEMENT_CONFIRMATION'
]);

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

function hash(value, field) {
  const text = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(text)) throw new Error(`${field}_invalid`);
  return text;
}
function verifyCreditorSettlement(input = {}) {
  const paymentId = uuid(input.payment_id, 'payment_id');
  const amount = Number(input.amount_in_minor);
  if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('amount_invalid');
  const currency = String(input.currency || '').toUpperCase();
  if (currency !== 'EUR') throw new Error('currency_invalid');

  const source = String(input.source || '').toUpperCase();
  if (!ALLOWED_SOURCES.has(source)) throw new Error('settlement_source_not_allowed');
  if (input.independently_verified !== true) {
    throw new Error('settlement_not_independently_verified');
  }

  const beneficiaryBinding = hash(
    input.beneficiary_binding_sha256,
    'beneficiary_binding_sha256'
  );
  const providerExecution = hash(
    input.provider_execution_receipt_sha256,
    'provider_execution_receipt_sha256'
  );
  const externalEvidence = hash(
    input.external_evidence_sha256,
    'external_evidence_sha256'
  );
  const confirmedAt = new Date(String(input.confirmed_at || ''));
  if (!Number.isFinite(confirmedAt.getTime())) throw new Error('confirmed_at_invalid');

  const receipt = {
    schema: 'atlas-payment-creditor-settlement-receipt-v2',
    payment_id: paymentId,
    amount_in_minor: amount,
    currency,
    beneficiary_binding_sha256: beneficiaryBinding,
    provider_execution_receipt_sha256: providerExecution,
    external_evidence_sha256: externalEvidence,
    source,
    independently_verified: true,
    creditor_confirmation_verified: true,
    confirmed_at: confirmedAt.toISOString(),
    value_moved: true
  };
  receipt.receipt_sha256 = sha256(JSON.stringify(receipt));
  return receipt;
}

module.exports = {
  ALLOWED_SOURCES,
  verifyCreditorSettlement
};
