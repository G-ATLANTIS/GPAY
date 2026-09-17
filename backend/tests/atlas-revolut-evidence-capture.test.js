#!/usr/bin/env node
'use strict';
const assert=require('node:assert/strict');
const {sha256Object,validateEvidence,deriveManualEvidence}=require('../../scripts/atlas-revolut-evidence-capture');
const {evaluateRevolutManualRelease,buildManualAppInstruction}=require('../../scripts/atlas-revolut-manual-release');
const now=new Date('2026-09-17T14:00:00Z');
const sourceType={
 CURRENT_ACCOUNT:'REVOLUT_ACCOUNT_CONFIRMATION',
 AVAILABLE_FUNDS:'REVOLUT_APP_BALANCE_CAPTURE',
 SINGLE_PAYMENT_LIMIT:'REVOLUT_SECURITY_LIMITS_CAPTURE',
 SCA_PATH:'REVOLUT_APP_SCA_OBSERVATION'
};
function proof(kind,data={},times={observed_at:'2026-09-17T13:59:00Z',expires_at:'2026-09-17T14:10:00Z'}){
 const payload={rail_id:'revolut-manual-sca',provider:'REVOLUT',evidence_kind:kind,source_type:sourceType[kind],probe_verified:true,...times,...data};
 return {probe_verified:true,source_reference:`manual-evidence:${kind}:receipt-1`,proof_payload:payload,proof_sha256:sha256Object(payload)};
}
const records={
 CURRENT_ACCOUNT:proof('CURRENT_ACCOUNT',{account_status_current:true,account_reference_masked:'REVO-••2148'}),
 AVAILABLE_FUNDS:proof('AVAILABLE_FUNDS',{available_funds_in_minor:30000000,currency:'EUR'}),
 SINGLE_PAYMENT_LIMIT:proof('SINGLE_PAYMENT_LIMIT',{max_single_payment_in_minor:30000000,currency:'EUR'}),
 SCA_PATH:proof('SCA_PATH',{user_app_approval_verified:true})
};
for(const k of Object.keys(records)) assert.equal(validateEvidence(records[k],{kind:k,now}).verified,true);
const ev=deriveManualEvidence({records,target_amount_in_minor:29490000,now});
assert.equal(ev.current_account_evidence_verified,true);
assert.equal(ev.available_funds_verified,true);
assert.equal(ev.available_funds_sufficient,true);
assert.equal(ev.bank_limit_verified,true);
assert.equal(ev.amount_covered,true);
assert.equal(ev.sca_path_verified,true);
assert.equal(ev.payment_endpoint_call_permitted,false);
let release=evaluateRevolutManualRelease({amount_in_minor:29490000,currency:'EUR',current_account_verified:ev.current_account_evidence_verified,funds_available_verified:ev.available_funds_verified,funds_sufficient:ev.available_funds_sufficient,bank_limit_verified:ev.bank_limit_verified,amount_covered:ev.amount_covered,sca_path_verified:ev.sca_path_verified,dealer_identity_verified:true,beneficiary_verified:true,invoice_verified:true,vin_verified:true,payment_reference_verified:true,exact_amount_bound:true,beneficiary_bound:true,fresh_owner_approval:true});
assert.equal(release.state,'READY_FOR_MANUAL_APP_ENTRY');
const instruction=buildManualAppInstruction({amount_in_minor:29490000,currency:'EUR',current_account_verified:true,funds_available_verified:true,funds_sufficient:true,bank_limit_verified:true,amount_covered:true,dealer_identity_verified:true,beneficiary_verified:true,invoice_verified:true,vin_verified:true,payment_reference_verified:true,exact_amount_bound:true,beneficiary_bound:true,sca_path_verified:true,fresh_owner_approval:true,raw_beneficiary_iban:'FR7612345678901234567890185',beneficiary_name:'Verified Dealer',payment_reference:'INV-TEST',intent_binding_sha256:'a'.repeat(64)});
assert.equal(instruction.requires_user_revolut_app_approval,true);
assert.equal(instruction.network_request_performed,false);
assert.equal(instruction.value_moved,false);
const lowFunds={...records,AVAILABLE_FUNDS:proof('AVAILABLE_FUNDS',{available_funds_in_minor:100000,currency:'EUR'})};
const low=deriveManualEvidence({records:lowFunds,target_amount_in_minor:29490000,now});
assert.equal(low.available_funds_verified,true);assert.equal(low.available_funds_sufficient,false);
release=evaluateRevolutManualRelease({amount_in_minor:29490000,currency:'EUR',current_account_verified:true,funds_available_verified:true,funds_sufficient:false});
assert.ok(release.blockers.includes('AVAILABLE_FUNDS_INSUFFICIENT'));
const stale=proof('CURRENT_ACCOUNT',{account_status_current:true},{observed_at:'2026-09-17T12:00:00Z',expires_at:'2026-09-17T12:10:00Z'});
assert.equal(validateEvidence(stale,{kind:'CURRENT_ACCOUNT',now}).verified,false);
const replay=proof('CURRENT_ACCOUNT',{account_status_current:true}); replay.proof_payload.rail_id='bunq-native-draft'; replay.proof_sha256=sha256Object(replay.proof_payload);
assert.equal(validateEvidence(replay,{kind:'CURRENT_ACCOUNT',now}).verified,false);
const wrongSource=proof('CURRENT_ACCOUNT',{account_status_current:true}); wrongSource.proof_payload.source_type='REVOLUT_APP_BALANCE_CAPTURE'; wrongSource.proof_sha256=sha256Object(wrongSource.proof_payload);
const wrongSourceResult=validateEvidence(wrongSource,{kind:'CURRENT_ACCOUNT',now});
assert.equal(wrongSourceResult.verified,false);
assert.ok(wrongSourceResult.reasons.includes('SOURCE_TYPE_NOT_ALLOWED_FOR_EVIDENCE_KIND'));
console.log('atlas-revolut-evidence-capture: PASS');
