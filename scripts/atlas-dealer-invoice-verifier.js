#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const HASH_RE = /^[0-9a-f]{64}$/i;
const VIN_RE = /^[A-HJ-NPR-Z0-9]{17}$/i;
const EXPECTED = Object.freeze({
  legal_name: "L'ART DE L'AUTOMOBILE",
  siren: '539983668',
  siret: '53998366800028',
  amount_in_minor: 29490000,
  currency: 'EUR'
});

function normText(value) {
  return String(value || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}
function hashOk(value) { return HASH_RE.test(String(value || '')); }
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, stable(value[k])]));
  return value;
}
function sha256Object(value) {
  return crypto.createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');
}
function evaluateDealerInvoice(input = {}) {
  const blockers = [];
  const amount = Number(input.amount_in_minor);
  const currency = String(input.currency || '').trim().toUpperCase();
  const dealerNameMatch = normText(input.dealer_legal_name) === normText(EXPECTED.legal_name);
  const sirenMatch = String(input.siren || '').replace(/\D/g,'') === EXPECTED.siren;
  const siretMatch = String(input.siret || '').replace(/\D/g,'') === EXPECTED.siret;
  const amountMatch = Number.isSafeInteger(amount) && amount === EXPECTED.amount_in_minor;
  const currencyMatch = currency === EXPECTED.currency;
  const invoiceHashOk = hashOk(input.invoice_sha256);
  const ibanHashOk = hashOk(input.beneficiary_iban_sha256);
  const vinOk = VIN_RE.test(String(input.vin || '').trim().toUpperCase());
  const referenceOk = String(input.payment_reference || '').trim().length > 0;
  const invoiceNumberOk = String(input.invoice_number || '').trim().length > 0;
  const beneficiaryNameMatch = normText(input.beneficiary_name) === normText(EXPECTED.legal_name);
  const thirdPartyVerified = input.beneficiary_independently_verified === true && hashOk(input.beneficiary_verification_sha256);

  if (!dealerNameMatch) blockers.push('DEALER_LEGAL_NAME_MISMATCH');
  if (!sirenMatch) blockers.push('DEALER_SIREN_MISMATCH');
  if (!siretMatch) blockers.push('DEALER_SIRET_MISMATCH');
  if (!amountMatch) blockers.push('INVOICE_AMOUNT_MISMATCH');
  if (!currencyMatch) blockers.push('INVOICE_CURRENCY_MISMATCH');
  if (!invoiceHashOk) blockers.push('INVOICE_SHA256_REQUIRED');
  if (!ibanHashOk) blockers.push('BENEFICIARY_IBAN_SHA256_REQUIRED');
  if (!vinOk) blockers.push('VIN_INVALID_OR_MISSING');
  if (!referenceOk) blockers.push('PAYMENT_REFERENCE_REQUIRED');
  if (!invoiceNumberOk) blockers.push('INVOICE_NUMBER_REQUIRED');
  if (!(beneficiaryNameMatch || thirdPartyVerified)) blockers.push('BENEFICIARY_ENTITY_MISMATCH');
  if (input.vin_independently_verified !== true) blockers.push('VIN_INDEPENDENT_VERIFICATION_REQUIRED');

  const binding = {
    schema: 'atlas-dealer-invoice-binding-v1',
    dealer_siren: EXPECTED.siren,
    dealer_siret: EXPECTED.siret,
    amount_in_minor: EXPECTED.amount_in_minor,
    currency: EXPECTED.currency,
    invoice_sha256: invoiceHashOk ? String(input.invoice_sha256).toLowerCase() : null,
    beneficiary_iban_sha256: ibanHashOk ? String(input.beneficiary_iban_sha256).toLowerCase() : null,
    vin: vinOk ? String(input.vin).trim().toUpperCase() : null,
    invoice_number: invoiceNumberOk ? String(input.invoice_number).trim() : null,
    payment_reference: referenceOk ? String(input.payment_reference).trim() : null,
    beneficiary_mode: beneficiaryNameMatch ? 'DEALER_ENTITY' : (thirdPartyVerified ? 'INDEPENDENTLY_VERIFIED_THIRD_PARTY' : 'UNVERIFIED'),
    blockers
  };
  const state = blockers.length ? 'BLOCKED' : 'VERIFIED_INVOICE_BENEFICIARY_BINDING';
  return {
    ...binding,
    state,
    binding_sha256: sha256Object(binding),
    payment_endpoint_call_permitted: false,
    network_payment_call_performed: false,
    value_moved: false
  };
}
if (require.main === module) {
  const result = evaluateDealerInvoice({});
  console.log(JSON.stringify(result, null, 2));
  if (result.state !== 'VERIFIED_INVOICE_BENEFICIARY_BINDING') process.exitCode = 2;
}

module.exports = { EXPECTED, VIN_RE, normText, sha256Object, evaluateDealerInvoice };
