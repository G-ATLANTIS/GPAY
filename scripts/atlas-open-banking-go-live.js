#!/usr/bin/env node
'use strict';

const REQUIRED = Object.freeze([
  'REGULATORY_IDENTITY_READY',
  'BANK_REGISTRATION_READY',
  'BENEFICIARY_VERIFIED',
  'BANK_LIMIT_VERIFIED',
  'AMOUNT_COVERED',
  'FRESH_CREDENTIALS',
  'SCA_PATH_VERIFIED',
  'CALLBACK_READBACK_VERIFIED',
  'IDEMPOTENCY_VERIFIED',
  'RECONCILIATION_VERIFIED',
  'OWNER_APPROVAL_VERIFIED',
  'HIGH_VALUE_APPROVAL_VERIFIED'
]);

function evaluateGoLive(evidence = {}) {
  const blockers = REQUIRED.filter(k => evidence[k] !== true).map(k => `MISSING_${k}`);
  const ready = blockers.length === 0;
  return {
    schema: 'atlas-open-banking-go-live-v1',
    state: ready ? 'LIVE_READY' : 'BLOCKED',
    blockers,
    atlas_open_banking_live: ready,
    payment_endpoint_call_permitted: false,
    first_transaction_policy: 'CONTROLLED_LOW_VALUE_OWNED_VERIFIED_BENEFICIARY',
    high_value_requires_separate_execution_authorization: true,
    payment_splitting_to_evade_limits: 'DENY',
    executed_equals_settled: false,
    value_moved: false
  };
}

module.exports = { REQUIRED, evaluateGoLive };
