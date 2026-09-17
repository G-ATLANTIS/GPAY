#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');

function sha256(value) {
  return crypto.createHash('sha256').update(String(value ?? '')).digest('hex');
}
function isHash(value) { return /^[0-9a-f]{64}$/i.test(String(value || '')); }

function createConsentReceipt(input = {}) {
  const now = input.created_at instanceof Date ? input.created_at : new Date();
  const expiresAt = input.expires_at instanceof Date ? input.expires_at : new Date(now.getTime() + 10 * 60 * 1000);
  if (!Number.isFinite(now.getTime()) || !Number.isFinite(expiresAt.getTime()) || expiresAt <= now) {
    throw new Error('consent_time_invalid');
  }
  for (const field of ['intent_binding_sha256','beneficiary_iban_sha256','invoice_sha256']) {
    if (!isHash(input[field])) throw new Error(`${field}_invalid`);
  }
  if (!Number.isSafeInteger(input.amount_in_minor) || input.amount_in_minor <= 0) throw new Error('amount_invalid');
  if (String(input.currency || '').toUpperCase() !== 'EUR') throw new Error('currency_invalid');
  if (input.owner_confirmed !== true) throw new Error('owner_confirmation_required');
  const receipt = {
    schema: 'atlas-open-banking-consent-v1',
    intent_binding_sha256: input.intent_binding_sha256,
    beneficiary_name: String(input.beneficiary_name || '').trim(),
    beneficiary_iban_sha256: input.beneficiary_iban_sha256,
    invoice_sha256: input.invoice_sha256,
    amount_in_minor: input.amount_in_minor,
    currency: 'EUR',
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    single_use: true,
    bank_credentials_collected: false,
    otp_collected: false
  };  if (!receipt.beneficiary_name) throw new Error('beneficiary_name_required');
  receipt.consent_sha256 = sha256(JSON.stringify(receipt));
  return Object.freeze(receipt);
}

function validateConsent(receipt, { now = new Date(), expected_intent_binding_sha256 } = {}) {
  if (!receipt || receipt.schema !== 'atlas-open-banking-consent-v1') throw new Error('consent_schema_invalid');
  const expected = { ...receipt };
  const supplied = expected.consent_sha256;
  delete expected.consent_sha256;
  if (!isHash(supplied) || sha256(JSON.stringify(expected)) !== supplied) throw new Error('consent_integrity_invalid');
  if (expected_intent_binding_sha256 && receipt.intent_binding_sha256 !== expected_intent_binding_sha256) {
    throw new Error('consent_intent_binding_mismatch');
  }
  const ts = now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(ts) || Date.parse(receipt.expires_at) <= ts) throw new Error('consent_expired');
  if (receipt.bank_credentials_collected !== false || receipt.otp_collected !== false) {
    throw new Error('consent_secret_boundary_violation');
  }
  return true;
}

module.exports = { createConsentReceipt, validateConsent, sha256 };
