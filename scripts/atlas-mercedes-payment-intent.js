#!/usr/bin/env node
'use strict';
const crypto = require('node:crypto');
const hashOk = v => /^[0-9a-f]{64}$/i.test(String(v || ''));
function evaluateMercedesIntent(input = {}) {
  const blockers = [];
  if (!hashOk(input.invoice_sha256)) blockers.push('INVOICE_REQUIRED');
  if (!hashOk(input.beneficiary_iban_sha256)) blockers.push('BENEFICIARY_IBAN_REQUIRED');
  if (!String(input.vin || '').trim()) blockers.push('VIN_REQUIRED');
  if (!String(input.payment_reference || '').trim()) blockers.push('PAYMENT_REFERENCE_REQUIRED');
  if (input.dealer_identity_verified !== true) blockers.push('DEALER_IDENTITY_VERIFICATION_REQUIRED');
  if (input.beneficiary_verified !== true) blockers.push('BENEFICIARY_VERIFICATION_REQUIRED');
  if (input.invoice_verified !== true) blockers.push('INVOICE_VERIFICATION_REQUIRED');
  if (input.vin_verified !== true) blockers.push('VIN_VERIFICATION_REQUIRED');
  const record = {
    schema: 'atlas-mercedes-payment-intent-v1',
    asset: 'Mercedes-Benz S 65 AMG Cabriolet',
    amount_in_minor: 29490000,
    currency: 'EUR',
    dealer: "L'Art de l'Automobile",
    state: blockers.length ? 'BLOCKED' : 'VERIFIED_INTENT_READY',
    blockers,
    payment_endpoint_called: false,
    value_moved: false
  };
  record.intent_sha256 = crypto.createHash('sha256').update(JSON.stringify(record)).digest('hex');
  return record;
}
if (require.main === module) console.log(JSON.stringify(evaluateMercedesIntent({}), null, 2));
module.exports = { evaluateMercedesIntent };
