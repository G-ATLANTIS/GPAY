#!/usr/bin/env node
'use strict';

const { evaluateProgram } = require('./atlas-open-banking-program-audit');
const { REQUIRED } = require('./atlas-open-banking-go-live');

function yes(env, key) { return String(env[key] || '').trim().toLowerCase() === 'true'; }
function present(env, key) { return typeof env[key] === 'string' && env[key].trim().length > 0; }

function currentStatus(env = process.env) {
  const external = [];
  const yapilyProd = env.YAPILY_ENV === 'production' && present(env, 'YAPILY_APPLICATION_KEY') && present(env, 'YAPILY_APPLICATION_SECRET') && yes(env, 'YAPILY_CONNECT_APPROVED');
  if (yapilyProd) external.push(2);
  const yapilyMax = Number(env.YAPILY_APPROVED_MAX_PAYMENT_EUR || 0);
  if (yapilyProd && yes(env, 'YAPILY_HIGH_VALUE_WAIVER_APPROVED') && yapilyMax >= 294900) external.push(3);
  if (yes(env, 'ATLAS_PISP_DNB_APPLICATION_SUBMITTED') && yes(env, 'ATLAS_PISP_DNB_AUTHORISED')) external.push(7);
  if (yes(env, 'ATLAS_PISP_EIDAS_READY')) external.push(8);
  if (yes(env, 'ATLAS_PISP_BANK_REGISTRATION_VERIFIED')) external.push(9);
  if (yes(env, 'ATLAS_DIRECT_BANK_EXECUTION_VERIFIED')) external.push(11);

  const goLiveEvidence = Object.fromEntries(REQUIRED.map(k => [k, yes(env, `ATLAS_GO_LIVE_${k}`)]));
  if (REQUIRED.every(k => goLiveEvidence[k] === true)) external.push(12);

  return evaluateProgram({
    implemented_steps: [1,2,3,4,5,6,7,8,9,10,11,12],
    externally_verified_steps: external,
    regulatory: {
      dnb_application_submitted: yes(env, 'ATLAS_PISP_DNB_APPLICATION_SUBMITTED'),
      dnb_authorisation_granted: yes(env, 'ATLAS_PISP_DNB_AUTHORISED'),
      dnb: {}, eidas: {}
    },
    migration: {
      sponsor_approved: yes(env, 'YAPILY_CONNECT_APPROVED'),
      sponsor_production_verified: yapilyProd,
      own_pisp_authorised: yes(env, 'ATLAS_PISP_DNB_AUTHORISED'),
      eidas_ready: yes(env, 'ATLAS_PISP_EIDAS_READY'),
      direct_bank_count: Number(env.ATLAS_DIRECT_BANK_VERIFIED_COUNT || 0),
      direct_bank_execution_verified: yes(env, 'ATLAS_DIRECT_BANK_EXECUTION_VERIFIED'),
      redundant_tsp_verified: yes(env, 'ATLAS_REDUNDANT_TSP_VERIFIED')
    },
    go_live: goLiveEvidence
  });
}
if (require.main === module) {
  const report = currentStatus(process.env);
  console.log(JSON.stringify(report, null, 2));
  if (report.state !== 'PROGRAM_LIVE_READY') process.exitCode = 2;
}

module.exports = { currentStatus };
