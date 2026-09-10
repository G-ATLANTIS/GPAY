'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function nonNegative(name, value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${name}_invalid`);
  return n;
}

function assessOperationalResilience({
  ledger_verified,
  receipt_chain_verified,
  checkpoint_verified,
  unresolved_unknown_count = 0,
  max_unresolved_unknown = 0,
  clock_drift_ms = 0,
  max_clock_drift_ms = 5000,
  emergency_freeze = false,
  now = Date.now(),
}) {
  const unknown = nonNegative('unresolved_unknown_count', unresolved_unknown_count);
  const maxUnknown = nonNegative('max_unresolved_unknown', max_unresolved_unknown);
  const drift = nonNegative('clock_drift_ms', clock_drift_ms);
  const maxDrift = nonNegative('max_clock_drift_ms', max_clock_drift_ms);
  const reasons = [];

  if (ledger_verified !== true) reasons.push('LEDGER_INTEGRITY_NOT_VERIFIED');
  if (receipt_chain_verified !== true) reasons.push('RECEIPT_CHAIN_NOT_VERIFIED');
  if (checkpoint_verified !== true) reasons.push('CHECKPOINT_NOT_VERIFIED');
  if (unknown > maxUnknown) reasons.push('UNRESOLVED_SETTLEMENT_UNCERTAINTY');
  if (drift > maxDrift) reasons.push('CLOCK_DRIFT_LIMIT_EXCEEDED');
  if (emergency_freeze === true) reasons.push('EMERGENCY_FREEZE_ACTIVE');

  const body = {
    schema: 'g-bank-operational-resilience-assessment/v2',
    state: reasons.length ? 'BLOCK' : 'PASS',
    ledger_verified: ledger_verified === true,
    receipt_chain_verified: receipt_chain_verified === true,
    checkpoint_verified: checkpoint_verified === true,
    unresolved_unknown_count: unknown,
    max_unresolved_unknown: maxUnknown,
    clock_drift_ms: drift,
    max_clock_drift_ms: maxDrift,
    emergency_freeze: emergency_freeze === true,
    reasons,
    assessed_at: new Date(now).toISOString(),
  };
  return Object.freeze({ ...body, assessment_sha256: sha256(canonicalJson(body)) });
}

module.exports = { assessOperationalResilience };
