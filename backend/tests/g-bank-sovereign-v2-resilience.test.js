'use strict';

const assert = require('node:assert/strict');
const { assessOperationalResilience } = require('../g-bank-sovereign-v2/operational-resilience');

const pass = assessOperationalResilience({
  ledger_verified: true,
  receipt_chain_verified: true,
  checkpoint_verified: true,
  unresolved_unknown_count: 0,
  max_unresolved_unknown: 0,
  clock_drift_ms: 20,
  max_clock_drift_ms: 5000,
  emergency_freeze: false,
});
assert.equal(pass.state, 'PASS');
assert.deepEqual(pass.reasons, []);

const unknown = assessOperationalResilience({
  ledger_verified: true,
  receipt_chain_verified: true,
  checkpoint_verified: true,
  unresolved_unknown_count: 1,
  max_unresolved_unknown: 0,
});
assert.equal(unknown.state, 'BLOCK');
assert.ok(unknown.reasons.includes('UNRESOLVED_SETTLEMENT_UNCERTAINTY'));

const drift = assessOperationalResilience({
  ledger_verified: true,
  receipt_chain_verified: true,
  checkpoint_verified: true,
  clock_drift_ms: 6000,
  max_clock_drift_ms: 5000,
});
assert.equal(drift.state, 'BLOCK');
assert.ok(drift.reasons.includes('CLOCK_DRIFT_LIMIT_EXCEEDED'));

const frozen = assessOperationalResilience({
  ledger_verified: true,
  receipt_chain_verified: true,
  checkpoint_verified: true,
  emergency_freeze: true,
});
assert.equal(frozen.state, 'BLOCK');
assert.ok(frozen.reasons.includes('EMERGENCY_FREEZE_ACTIVE'));

const integrity = assessOperationalResilience({
  ledger_verified: false,
  receipt_chain_verified: false,
  checkpoint_verified: false,
});
assert.equal(integrity.state, 'BLOCK');
assert.ok(integrity.reasons.includes('LEDGER_INTEGRITY_NOT_VERIFIED'));
assert.ok(integrity.reasons.includes('RECEIPT_CHAIN_NOT_VERIFIED'));
assert.ok(integrity.reasons.includes('CHECKPOINT_NOT_VERIFIED'));

console.log('G-BANK sovereign v2 operational resilience tests: PASS');
