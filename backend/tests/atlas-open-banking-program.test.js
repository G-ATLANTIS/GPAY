#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createConsentReceipt, validateConsent } = require('../../scripts/atlas-open-banking-consent');
const { evaluateRegulatoryReadiness } = require('../../scripts/atlas-open-banking-regulatory');
const { certificateRecord, evaluateCertificatePair } = require('../../scripts/atlas-open-banking-certificates');
const { institutionRegistration, evaluateRegistration } = require('../../scripts/atlas-open-banking-institutions');
const { evaluateMigration } = require('../../scripts/atlas-open-banking-migration');
const { evaluateGoLive, REQUIRED } = require('../../scripts/atlas-open-banking-go-live');
const { evaluateProgram } = require('../../scripts/atlas-open-banking-program-audit');
const { OwnPispAdapter, DirectBankAdapter } = require('../../scripts/atlas-open-banking-adapters');
const h = v => crypto.createHash('sha256').update(v).digest('hex');

const consent = createConsentReceipt({
  intent_binding_sha256: h('intent'), beneficiary_name: 'Dealer', beneficiary_iban_sha256: h('iban'),
  invoice_sha256: h('invoice'), amount_in_minor: 29_490_000, currency: 'EUR', owner_confirmed: true
});
assert.equal(validateConsent(consent, { expected_intent_binding_sha256: h('intent') }), true);

const reg = evaluateRegulatoryReadiness({});
assert.equal(reg.own_pisp_execution_ready, false);
assert(reg.blockers.includes('DNB_AUTHORISATION_NOT_GRANTED'));

const future = new Date(Date.now() + 86400000).toISOString();
const past = new Date(Date.now() - 86400000).toISOString();
const qwac = certificateRecord({ type: 'QWAC', serial: '1', issuer: 'QTSP', not_before: past, not_after: future, status: 'ACTIVE' });
const qseal = certificateRecord({ type: 'QSEAL', serial: '2', issuer: 'QTSP', not_before: past, not_after: future, status: 'ACTIVE' });
assert.equal(evaluateCertificatePair({ qwac, qseal }).state, 'READY');const registration = institutionRegistration({
  institution_id: 'bank-nl-test', provider: 'atlas-own-pisp', environment: 'PRODUCTION',
  registration_state: 'REGISTERED', pisp_identity: 'atlas-pisp', callback_origin: 'https://bank.example',
  credentials_present: true, certificate_binding_verified: true, last_probe_verified: true,
  last_probe_at: new Date().toISOString()
});
assert.equal(evaluateRegistration(registration).state, 'READY');

assert.equal(evaluateMigration({ sponsor_approved: true, sponsor_production_verified: true }).phase, 'A');
assert.equal(evaluateMigration({ own_pisp_authorised: true, eidas_ready: true }).phase, 'B');
assert.equal(evaluateMigration({ own_pisp_authorised: true, eidas_ready: true, direct_bank_count: 1, direct_bank_execution_verified: true }).phase, 'C');
assert.equal(evaluateMigration({ own_pisp_authorised: true, eidas_ready: true, direct_bank_count: 3, direct_bank_execution_verified: true, redundant_tsp_verified: true }).phase, 'D');

const allGreen = Object.fromEntries(REQUIRED.map(k => [k, true]));
assert.equal(evaluateGoLive(allGreen).state, 'LIVE_READY');
assert.equal(evaluateGoLive({}).state, 'BLOCKED');

const own = new OwnPispAdapter({ env: {
  ATLAS_PISP_DNB_AUTHORISED: 'true', ATLAS_PISP_EIDAS_READY: 'true', ATLAS_PISP_BANK_REGISTRATION_VERIFIED: 'true',
  ATLAS_PISP_PRODUCTION: 'true', ATLAS_PISP_VERIFIED_MAX_PAYMENT_EUR: '300000'
}});
assert.equal(own.capabilitySnapshot({ intent: { amount_in_minor: 29_490_000 } }).execution_authorized, true);

const direct = new DirectBankAdapter({ bank_id: 'demo', env: {
  ATLAS_BANK_DEMO_AUTHENTICATED: 'true', ATLAS_BANK_DEMO_PAYMENT_WRITE_VERIFIED: 'true',
  ATLAS_BANK_DEMO_LIMIT_EVIDENCE_VERIFIED: 'true', ATLAS_BANK_DEMO_PRODUCTION: 'true',
  ATLAS_BANK_DEMO_VERIFIED_MAX_PAYMENT_EUR: '300000'
}});
assert.equal(direct.capabilitySnapshot({ intent: { amount_in_minor: 29_490_000 } }).execution_authorized, true);const program = evaluateProgram({
  implemented_steps: [1,2,3,4,5,6,7,8,9,10,11,12],
  externally_verified_steps: [],
  regulatory: {},
  migration: {},
  go_live: {}
});
assert.equal(program.all_implementation_complete, true);
assert.equal(program.all_external_complete, false);
assert.equal(program.state, 'PROGRAM_BLOCKED');
assert.equal(program.payment_endpoint_call_permitted, false);
assert.equal(program.value_moved, false);

console.log('atlas-open-banking-program: PASS');
