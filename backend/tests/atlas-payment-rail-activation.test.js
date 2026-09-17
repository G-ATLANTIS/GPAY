#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { activationMatrix, validProof, sha256Object } = require('../../scripts/atlas-payment-rail-activation');
const { probePlan } = require('../../scripts/atlas-payment-rail-probe-contracts');
const h = s => crypto.createHash('sha256').update(s).digest('hex');
const now = new Date('2026-09-17T13:45:00.000Z');

const userEnv = {ATLAS_RAIL_BUNQ_APPLICABLE:'false'};
const empty = activationMatrix({env:userEnv, evidence:{}, now});
assert.equal(empty.schema, 'atlas-payment-rail-activation-matrix-v2');
assert.equal(empty.total_rails, 8);
assert.equal(empty.applicable_rail_count, 7);
assert.equal(empty.not_applicable_count, 1);
assert.equal(empty.primary_payment_path_id, 'revolut-manual-sca');
assert.equal(empty.next_activation_rail_id, 'revolut-manual-sca');
assert.equal(empty.verified_read_only_count, 0);
assert.equal(empty.verified_manual_account_count, 0);
assert.equal(empty.rails.find(r=>r.rail_id==='bunq-native-draft').state, 'NOT_APPLICABLE');
assert.equal(empty.rails.find(r=>r.rail_id==='revolut-manual-sca').state, 'READY_FOR_MANUAL_ACCOUNT_VERIFICATION');
assert.equal(empty.rails.find(r=>r.rail_id==='revolut-open-banking').state, 'BLOCKED_EXTERNAL_ONBOARDING');
assert.equal(empty.payment_write_enabled, false);
assert.equal(empty.provider_call_permitted, false);
assert.equal(empty.value_moved, false);

const manualPlan = probePlan({rail_id:'revolut-manual-sca', env:userEnv, now});
assert.equal(manualPlan.can_run_offline_verification, true);
assert.equal(manualPlan.can_run_readonly_network_probe, false);
assert.equal(manualPlan.financial_writes_allowed, false);

const proofPayload = {
  rail_id:'revolut-manual-sca', probe_verified:true, proof_kind:'CURRENT_ACCOUNT_EVIDENCE',
  observed_at:'2026-09-17T13:44:00Z', expires_at:'2026-09-18T13:44:00Z',
  provider_evidence_sha256:h('fresh-revolut-account-evidence')
};
const proof = {probe_verified:true, proof_payload:proofPayload, proof_sha256:sha256Object(proofPayload), source_reference:'provider-evidence:revolut:current-account'};
assert.equal(validProof(proof, now, 'revolut-manual-sca'), true);
const verified = activationMatrix({env:userEnv, evidence:{'revolut-manual-sca':proof}, now});
assert.equal(verified.verified_manual_account_count, 1);
assert.equal(verified.rails.find(r=>r.rail_id==='revolut-manual-sca').state, 'ACCOUNT_EVIDENCE_VERIFIED');
assert.equal(verified.payment_write_enabled, false);
assert.equal(verified.provider_call_permitted, false);

const stalePayload = {...proofPayload, expires_at:'2026-09-17T13:40:00Z'};
assert.equal(validProof({...proof, proof_payload:stalePayload, proof_sha256:sha256Object(stalePayload)}, now, 'revolut-manual-sca'), false);
const wrongRailPayload = {...proofPayload, rail_id:'revolut-open-banking'};
assert.equal(validProof({...proof, proof_payload:wrongRailPayload, proof_sha256:sha256Object(wrongRailPayload)}, now, 'revolut-manual-sca'), false);

const obEnv = {...userEnv, REVOLUT_PISP_TRANSPORT_VERIFIED:'true', REVOLUT_OPEN_BANKING_ROUTE_VERIFIED:'true', ATLAS_ALLOW_READONLY_NETWORK_PROBE:'true'};
const obPlan = probePlan({rail_id:'revolut-open-banking', env:obEnv, now});
assert.equal(obPlan.activation_state, 'READY_FOR_READONLY_PROBE');
assert.equal(obPlan.can_run_readonly_network_probe, false); // executor deliberately not installed yet
assert.equal(obPlan.payment_endpoint_call_permitted, false);

console.log('atlas-payment-rail-activation-v2: PASS');
