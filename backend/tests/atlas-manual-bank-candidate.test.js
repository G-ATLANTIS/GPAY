#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const { evaluateManualBankCandidate } = require('../../scripts/atlas-manual-bank-candidate');

const now = new Date('2026-09-17T16:00:00Z');
const base = {
  bank_id:'abn-amro',
  rail_id:'abn-amro-manual-sca',
  target_amount_in_minor:29490000,
  historical_account_association_verified:true,
  current_account_verified:false,
  available_funds_verified:false,
  available_funds_in_minor:0,
  public_standard_single_payment_max_in_minor:25000000,
  public_constraint_source:'https://www.abnamro.nl/nl/prive/internet-en-mobiel/hoeveel-kan-ik-maximaal-overboeken.html',
  public_constraint_expires_at:'2026-10-17T23:59:59Z',
  elevated_tier_verified:false,
  elevated_single_payment_max_in_minor:0,
  sca_path_verified:false
};
const blocked = evaluateManualBankCandidate(base, now);
assert.equal(blocked.state,'BLOCKED_PUBLIC_SINGLE_PAYMENT_LIMIT');
assert.ok(blocked.blockers.includes('CURRENT_ACCOUNT_EVIDENCE_REQUIRED'));
assert.ok(blocked.blockers.includes('SINGLE_PAYMENT_LIMIT_INSUFFICIENT'));
assert.equal(blocked.payment_splitting_to_evade_limits,'DENY');
assert.equal(blocked.payment_endpoint_call_permitted,false);
assert.equal(blocked.value_moved,false);

const elevated = evaluateManualBankCandidate({
  ...base,
  current_account_verified:true,
  available_funds_verified:true,
  available_funds_in_minor:30000000,
  elevated_tier_verified:true,
  elevated_single_payment_max_in_minor:100000000,
  sca_path_verified:true
}, now);
assert.equal(elevated.state,'READY_FOR_MANUAL_BANK_ENTRY');
assert.equal(elevated.limit_class,'ELEVATED_TIER_VERIFIED');
assert.equal(elevated.requires_user_bank_approval,true);
assert.equal(elevated.network_payment_call_performed,false);

const stale = evaluateManualBankCandidate({
  ...base,
  public_constraint_expires_at:'2026-09-16T00:00:00Z'
}, now);
assert.ok(stale.blockers.includes('PUBLIC_LIMIT_EVIDENCE_STALE_OR_MISSING'));
assert.equal(stale.payment_endpoint_call_permitted,false);
console.log('atlas-manual-bank-candidate: PASS');
