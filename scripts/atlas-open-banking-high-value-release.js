#!/usr/bin/env node
'use strict';

function evaluateHighValueRelease(input = {}) {
  const amount = Number(input.amount_in_minor);
  if (!Number.isSafeInteger(amount) || amount < 10_000_000) throw new Error('high_value_amount_required');
  const blockers = [];
  const checks = [
    ['bank_limit_verified', 'BANK_LIMIT_VERIFICATION_REQUIRED'],
    ['amount_covered', 'BANK_LIMIT_INSUFFICIENT'],
    ['beneficiary_verified', 'BENEFICIARY_VERIFICATION_REQUIRED'],
    ['invoice_verified', 'INVOICE_VERIFICATION_REQUIRED'],
    ['vin_verified', 'VIN_VERIFICATION_REQUIRED'],
    ['callback_readback_verified', 'CALLBACK_READBACK_VERIFICATION_REQUIRED'],
    ['canary_reconciled', 'CONTROLLED_CANARY_REQUIRED'],
    ['idempotency_verified', 'IDEMPOTENCY_VERIFICATION_REQUIRED'],
    ['sca_path_verified', 'SCA_PATH_VERIFICATION_REQUIRED'],
    ['provider_or_bank_live_verified', 'LIVE_RAIL_VERIFICATION_REQUIRED'],
    ['fresh_owner_approval', 'FRESH_OWNER_APPROVAL_REQUIRED'],
    ['high_value_execution_authorization', 'HIGH_VALUE_EXECUTION_AUTHORIZATION_REQUIRED']
  ];
  for (const [field, code] of checks) if (input[field] !== true) blockers.push(code);
  return {
    schema: 'atlas-open-banking-high-value-release-v1',
    amount_in_minor: amount,
    currency: 'EUR',
    state: blockers.length ? 'BLOCKED' : 'READY_FOR_PROVIDER_CREATION',
    blockers,
    payment_splitting_to_evade_limits: 'DENY',
    executed_equals_settled: false,
    payment_endpoint_called: false,
    value_moved: false
  };
}

if (require.main === module) {
  const result = evaluateHighValueRelease({ amount_in_minor: 29_490_000 });
  console.log(JSON.stringify(result, null, 2));
  if (result.state !== 'READY_FOR_PROVIDER_CREATION') process.exitCode = 2;
}

module.exports = { evaluateHighValueRelease };
