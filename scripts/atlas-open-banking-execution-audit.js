#!/usr/bin/env node
'use strict';
const { discover } = require('./atlas-open-banking-bank-discovery');
const { evaluateCanary } = require('./atlas-open-banking-canary');
const { evaluateHighValueRelease } = require('./atlas-open-banking-high-value-release');
const { evaluateMercedesIntent } = require('./atlas-mercedes-payment-intent');
function audit(env = process.env) {
  const bank = discover(env);
  const canary = evaluateCanary({ amount_in_minor: 1 });
  const high = evaluateHighValueRelease({ amount_in_minor: 29490000 });
  const mercedes = evaluateMercedesIntent({});
  return {
    schema: 'atlas-open-banking-execution-audit-v1',
    step_1_bank_native: bank,
    step_2_beneficiary: { state: mercedes.blockers.includes('BENEFICIARY_VERIFICATION_REQUIRED') ? 'BLOCKED' : 'VERIFIED' },
    step_3_yapily: { state: 'AWAITING_EXTERNAL_RESPONSE' },
    step_4_callbacks: { return_uri_live: true, provider_webhook_verified: false, readback_verified: false, state: 'PARTIAL' },
    step_5_canary: canary,
    step_6_high_value_gate: high,
    step_7_mercedes_payment: mercedes,
    step_8_own_pisp: { application_pack_present: true, eidas_plan_present: true, state: 'PREPARED_EXTERNAL_APPROVAL_REQUIRED' },
    overall_state: 'BLOCKED_EXTERNAL_EVIDENCE_REQUIRED',
    payment_endpoint_call_permitted: false,
    value_moved: false
  };
}
if (require.main === module) { console.log(JSON.stringify(audit(), null, 2)); process.exitCode = 2; }
module.exports = { audit };
