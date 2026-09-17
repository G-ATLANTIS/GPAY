#!/usr/bin/env node
'use strict';

function isTrue(v) { return String(v || '').toLowerCase() === 'true'; }
function amountMinor(v) {
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error('amount_in_minor_invalid');
  return n;
}

function evaluateCanary(input = {}) {
  const amount = amountMinor(input.amount_in_minor);
  const blockers = [];
  if (amount > 100) blockers.push('CANARY_AMOUNT_MUST_BE_AT_MOST_1_EUR');
  if (input.controlled_beneficiary_verified !== true) blockers.push('CONTROLLED_BENEFICIARY_REQUIRED');
  if (input.bank_native_readiness_verified !== true) blockers.push('BANK_NATIVE_READINESS_REQUIRED');
  if (input.callback_readback_verified !== true) blockers.push('CALLBACK_READBACK_REQUIRED');
  if (input.idempotency_verified !== true) blockers.push('IDEMPOTENCY_REQUIRED');
  if (input.explicit_execution_authorization !== true) blockers.push('EXPLICIT_EXECUTION_AUTHORIZATION_REQUIRED');
  return {
    schema: 'atlas-open-banking-canary-v1',
    amount_in_minor: amount,
    currency: 'EUR',
    state: blockers.length ? 'BLOCKED' : 'READY_FOR_EXPLICIT_EXECUTION',
    blockers,
    payment_endpoint_called: false,
    value_moved: false
  };
}

if (require.main === module) {
  const result = evaluateCanary({
    amount_in_minor: Number(process.env.ATLAS_CANARY_AMOUNT_MINOR || 1),
    controlled_beneficiary_verified: isTrue(process.env.ATLAS_CANARY_BENEFICIARY_VERIFIED),
    bank_native_readiness_verified: isTrue(process.env.ATLAS_BANK_NATIVE_READINESS_VERIFIED),
    callback_readback_verified: isTrue(process.env.ATLAS_CALLBACK_READBACK_VERIFIED),
    idempotency_verified: isTrue(process.env.ATLAS_IDEMPOTENCY_VERIFIED),
    explicit_execution_authorization: isTrue(process.env.ATLAS_CANARY_EXECUTION_AUTHORIZED)
  });
  console.log(JSON.stringify(result, null, 2));
  if (result.state !== 'READY_FOR_EXPLICIT_EXECUTION') process.exitCode = 2;
}

module.exports = { evaluateCanary };
