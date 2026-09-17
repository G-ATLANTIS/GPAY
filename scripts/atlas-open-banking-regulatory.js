#!/usr/bin/env node
'use strict';

const REQUIRED_DNB = Object.freeze([
  'LEGAL_ENTITY_READY','PAYMENT_SERVICE_7_SCOPE_DEFINED','GOVERNANCE_READY',
  'FIT_PROPER_READY','RISK_FRAMEWORK_READY','ICT_SECURITY_READY',
  'INCIDENT_MANAGEMENT_READY','BUSINESS_CONTINUITY_READY','OUTSOURCING_POLICY_READY',
  'PII_OR_GUARANTEE_READY','FINANCIAL_PLAN_READY','EHERKENNING_READY'
]);
const REQUIRED_EIDAS = Object.freeze([
  'PISP_AUTHORISATION_GRANTED','QWAC_ISSUED','QSEAL_ISSUED',
  'PRIVATE_KEYS_NON_EXPORTABLE','CERTIFICATE_EXPIRY_MONITORED'
]);

function evaluateChecklist(required, evidence = {}) {
  const blockers = required.filter(key => evidence[key] !== true).map(key => `MISSING_${key}`);
  return { state: blockers.length ? 'BLOCKED' : 'READY', blockers };
}

function evaluateRegulatoryReadiness(input = {}) {
  const dnb = evaluateChecklist(REQUIRED_DNB, input.dnb);
  const eidas = evaluateChecklist(REQUIRED_EIDAS, input.eidas);
  return {
    schema: 'atlas-regulatory-readiness-v1',
    dnb_application: dnb,
    own_pisp_identity: eidas,
    own_pisp_execution_ready: dnb.state === 'READY' && eidas.state === 'READY' && input.dnb_application_submitted === true && input.dnb_authorisation_granted === true,
    blockers: [...dnb.blockers, ...eidas.blockers,
      ...(input.dnb_application_submitted === true ? [] : ['DNB_APPLICATION_NOT_SUBMITTED']),
      ...(input.dnb_authorisation_granted === true ? [] : ['DNB_AUTHORISATION_NOT_GRANTED'])],
    provider_call_permitted: false,
    value_moved: false
  };
}
module.exports = {
  REQUIRED_DNB,
  REQUIRED_EIDAS,
  evaluateChecklist,
  evaluateRegulatoryReadiness
};
