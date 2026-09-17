#!/usr/bin/env node
'use strict';
const { activationMatrix } = require('./atlas-payment-rail-activation');
const { evaluateCanary } = require('./atlas-open-banking-canary');
const { evaluateHighValueRelease } = require('./atlas-open-banking-high-value-release');
const { evaluateMercedesIntent } = require('./atlas-mercedes-payment-intent');
const { evaluateRevolutManualRelease } = require('./atlas-revolut-manual-release');

function audit(env = process.env) {
  const activation = activationMatrix({env});
  const canary = evaluateCanary({ amount_in_minor: 1 });
  const automatedHigh = evaluateHighValueRelease({ amount_in_minor: 29490000 });
  const manualHigh = evaluateRevolutManualRelease({ amount_in_minor: 29490000, currency: 'EUR' });
  const mercedes = evaluateMercedesIntent({});
  const primary = activation.rails.find(r => r.rail_id === activation.primary_payment_path_id) || null;
  const revolutOb = activation.rails.find(r => r.rail_id === 'revolut-open-banking') || null;
  return {
    schema: 'atlas-open-banking-execution-audit-v2',
    step_1_primary_payment_path: {
      rail_id: activation.primary_payment_path_id,
      state: primary?.state || 'BLOCKED',
      execution_mode: 'MANUAL_BANK_SCA',
      payment_endpoint_call_permitted: false,
      value_moved: false
    },
    step_2_beneficiary: { state: mercedes.blockers.includes('BENEFICIARY_VERIFICATION_REQUIRED') ? 'BLOCKED' : 'VERIFIED' },
    step_3_revolut_open_banking_automation: {
      rail_id: 'revolut-open-banking',
      state: revolutOb?.state || 'BLOCKED',
      transport_provider: null,
      payment_endpoint_call_permitted: false
    },
    step_4_callbacks_for_automated_rails: { return_uri_live: true, provider_webhook_verified: false, readback_verified: false, state: 'PARTIAL' },
    step_5_controlled_canary_for_automated_rails: canary,
    step_6_automated_high_value_gate: automatedHigh,
    step_6_manual_revolut_gate: manualHigh,
    step_7_mercedes_payment: mercedes,
    step_8_own_pisp: { application_pack_present: true, eidas_plan_present: true, state: 'PREPARED_EXTERNAL_APPROVAL_REQUIRED' },
    overall_state: 'BLOCKED_EXTERNAL_EVIDENCE_REQUIRED',
    payment_endpoint_call_permitted: false,
    value_moved: false
  };
}
if (require.main === module) { console.log(JSON.stringify(audit(), null, 2)); process.exitCode = 2; }
module.exports = { audit };
