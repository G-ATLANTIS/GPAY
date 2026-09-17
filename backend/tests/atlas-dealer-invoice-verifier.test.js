#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const { evaluateDealerInvoice } = require('../../scripts/atlas-dealer-invoice-verifier');

const base = {
  dealer_legal_name: "L'ART DE L'AUTOMOBILE",
  siren: '539 983 668',
  siret: '539 983 668 00028',
  amount_in_minor: 29490000,
  currency: 'EUR',
  invoice_sha256: 'a'.repeat(64),
  beneficiary_iban_sha256: 'b'.repeat(64),
  vin: 'WDD2174791A123456',
  vin_independently_verified: true,
  invoice_number: 'INV-TEST-001',
  payment_reference: 'INV-TEST-001',
  beneficiary_name: "L'ART DE L'AUTOMOBILE"
};

assert.equal(evaluateDealerInvoice({}).state, 'BLOCKED');
const good = evaluateDealerInvoice(base);
assert.equal(good.state, 'VERIFIED_INVOICE_BENEFICIARY_BINDING');
assert.equal(good.payment_endpoint_call_permitted, false);
assert.equal(good.value_moved, false);
assert.equal(evaluateDealerInvoice({...base, siren:'000000000'}).blockers.includes('DEALER_SIREN_MISMATCH'), true);
assert.equal(evaluateDealerInvoice({...base, amount_in_minor:29489999}).blockers.includes('INVOICE_AMOUNT_MISMATCH'), true);
assert.equal(evaluateDealerInvoice({...base, vin:'TESTVIN'}).blockers.includes('VIN_INVALID_OR_MISSING'), true);
assert.equal(evaluateDealerInvoice({...base, beneficiary_name:'OTHER ENTITY'}).blockers.includes('BENEFICIARY_ENTITY_MISMATCH'), true);
const thirdParty = evaluateDealerInvoice({
  ...base,
  beneficiary_name:'ESCROW ENTITY',
  beneficiary_independently_verified:true,
  beneficiary_verification_sha256:'c'.repeat(64)
});
assert.equal(thirdParty.state, 'VERIFIED_INVOICE_BENEFICIARY_BINDING');
assert.equal(thirdParty.beneficiary_mode, 'INDEPENDENTLY_VERIFIED_THIRD_PARTY');
assert.equal(thirdParty.network_payment_call_performed, false);
console.log('atlas-dealer-invoice-verifier: PASS');
