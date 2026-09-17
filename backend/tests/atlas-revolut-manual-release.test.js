#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const { evaluateRevolutManualRelease, buildManualAppInstruction } = require('../../scripts/atlas-revolut-manual-release');

const blocked = evaluateRevolutManualRelease({amount_in_minor:29490000,currency:'EUR'});
assert.equal(blocked.state,'BLOCKED');
assert.ok(blocked.blockers.includes('CURRENT_REVOLUT_ACCOUNT_EVIDENCE_REQUIRED'));
assert.ok(blocked.blockers.includes('BANK_LIMIT_VERIFICATION_REQUIRED'));
assert.ok(blocked.blockers.includes('FRESH_OWNER_APPROVAL_REQUIRED'));
assert.equal(blocked.payment_endpoint_call_permitted,false);
assert.equal(blocked.value_moved,false);
assert.equal(blocked.payment_splitting_to_evade_limits,'DENY');

const readyInput = {
  amount_in_minor:29490000,currency:'EUR', current_account_verified:true,
  funds_available_verified:true, bank_limit_verified:true, amount_covered:true,
  dealer_identity_verified:true, beneficiary_verified:true, invoice_verified:true,
  vin_verified:true, payment_reference_verified:true, exact_amount_bound:true,
  beneficiary_bound:true, sca_path_verified:true, fresh_owner_approval:true,
  raw_beneficiary_iban:'FR7612345678901234567890185', beneficiary_name:'Dealer',
  payment_reference:'INVOICE-EXACT', intent_binding_sha256:'a'.repeat(64)
};
const ready = evaluateRevolutManualRelease(readyInput);
assert.equal(ready.state,'READY_FOR_MANUAL_APP_ENTRY');
assert.equal(ready.requires_user_revolut_app_approval,true);
assert.equal(ready.payment_endpoint_call_permitted,false);
const instruction = buildManualAppInstruction(readyInput);
assert.equal(instruction.network_request_performed,false);
assert.equal(instruction.value_moved,false);
assert.equal(instruction.requires_user_revolut_app_approval,true);
console.log('atlas-revolut-manual-release: PASS');
