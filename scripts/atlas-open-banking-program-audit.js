#!/usr/bin/env node
'use strict';

const { evaluateRegulatoryReadiness } = require('./atlas-open-banking-regulatory');
const { evaluateGoLive } = require('./atlas-open-banking-go-live');
const { evaluateMigration } = require('./atlas-open-banking-migration');

const STEP_NAMES = Object.freeze({
  1: 'PROVIDER_NEUTRAL_CORE',
  2: 'YAPILY_CONNECT_ADAPTER',
  3: 'HIGH_VALUE_COMMERCIAL_GATE',
  4: 'BANK_NATIVE_FALLBACK',
  5: 'CAPABILITY_REGISTRY',
  6: 'CONSENT_AND_SCA',
  7: 'DNB_PISP_TRACK',
  8: 'EIDAS_IDENTITY',
  9: 'BANK_REGISTRATIONS',
  10: 'SPONSOR_TO_OWN_PISP_MIGRATION',
  11: 'DIRECT_BANK_CONNECTIVITY',
  12: 'PRODUCTION_GO_LIVE_GATE'
});

function evaluateProgram(input = {}) {
  const regulatory = evaluateRegulatoryReadiness(input.regulatory || {});
  const migration = evaluateMigration(input.migration || {});
  const goLive = evaluateGoLive(input.go_live || {});
  const implemented = new Set(input.implemented_steps || []);
  const externallyVerified = new Set(input.externally_verified_steps || []);
  const steps = {};
  for (let i = 1; i <= 12; i += 1) {
    const codeDone = implemented.has(i);
    const externalRequired = [2,3,7,8,9,11,12].includes(i);
    const externalDone = externallyVerified.has(i);
    steps[i] = {
      name: STEP_NAMES[i],
      implementation: codeDone ? 'IMPLEMENTED' : 'MISSING',
      external_state: externalRequired ? (externalDone ? 'VERIFIED' : 'BLOCKED_EXTERNAL') : 'NOT_REQUIRED',
      complete: codeDone && (!externalRequired || externalDone)
    };
  }  return {
    schema: 'atlas-open-banking-program-audit-v1',
    steps,
    regulatory,
    migration,
    go_live: goLive,
    all_implementation_complete: Object.values(steps).every(s => s.implementation === 'IMPLEMENTED'),
    all_external_complete: Object.values(steps).every(s => s.complete),
    state: Object.values(steps).every(s => s.complete) && goLive.state === 'LIVE_READY'
      ? 'PROGRAM_LIVE_READY'
      : 'PROGRAM_BLOCKED',
    payment_endpoint_call_permitted: false,
    value_moved: false
  };
}

module.exports = { STEP_NAMES, evaluateProgram };
