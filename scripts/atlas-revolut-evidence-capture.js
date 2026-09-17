#!/usr/bin/env node
'use strict';
const crypto = require('node:crypto');
const RAIL_ID = 'revolut-manual-sca';
const PROVIDER = 'REVOLUT';
const KINDS = Object.freeze(['CURRENT_ACCOUNT','AVAILABLE_FUNDS','SINGLE_PAYMENT_LIMIT','SCA_PATH']);
const SOURCE_TYPES = Object.freeze({
  CURRENT_ACCOUNT: Object.freeze(['REVOLUT_ACCOUNT_CONFIRMATION','REVOLUT_ACCOUNT_API_READBACK']),
  AVAILABLE_FUNDS: Object.freeze(['REVOLUT_APP_BALANCE_CAPTURE','REVOLUT_ACCOUNT_API_READBACK']),
  SINGLE_PAYMENT_LIMIT: Object.freeze(['REVOLUT_SECURITY_LIMITS_CAPTURE','REVOLUT_ACCOUNT_API_READBACK']),
  SCA_PATH: Object.freeze(['REVOLUT_APP_SCA_OBSERVATION','REVOLUT_TRANSFER_PREVIEW'])
});
function stable(v){if(Array.isArray(v))return v.map(stable);if(v&&typeof v==='object')return Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])]));return v;}
function sha256Object(v){return crypto.createHash('sha256').update(JSON.stringify(stable(v))).digest('hex');}
function validTime(payload, now){const o=Date.parse(payload.observed_at||'');const e=Date.parse(payload.expires_at||'');const t=now.getTime();return Number.isFinite(o)&&Number.isFinite(e)&&o<=t+60000&&e>t;}
function validateEvidence(record,{kind,now=new Date()}={}){
  const reasons=[]; const payload=record?.proof_payload;
  if(!KINDS.includes(kind)) throw new Error('evidence_kind_invalid');
  if(!record||record.probe_verified!==true) reasons.push('PROBE_NOT_VERIFIED');
  if(!String(record?.source_reference||'').trim()) reasons.push('SOURCE_REFERENCE_REQUIRED');
  if(!payload||typeof payload!=='object'||Array.isArray(payload)) reasons.push('PROOF_PAYLOAD_REQUIRED');
  if(payload){
    if(payload.rail_id!==RAIL_ID) reasons.push('RAIL_ID_MISMATCH');
    if(payload.provider!==PROVIDER) reasons.push('PROVIDER_MISMATCH');
    if(payload.evidence_kind!==kind) reasons.push('EVIDENCE_KIND_MISMATCH');
    if(!SOURCE_TYPES[kind].includes(String(payload.source_type||''))) reasons.push('SOURCE_TYPE_NOT_ALLOWED_FOR_EVIDENCE_KIND');
    if(payload.probe_verified!==true) reasons.push('PAYLOAD_NOT_VERIFIED');
    if(!validTime(payload,now)) reasons.push('EVIDENCE_STALE_OR_INVALID_TIME');
    if(!/^[0-9a-f]{64}$/i.test(String(record?.proof_sha256||''))||sha256Object(payload)!==String(record.proof_sha256||'').toLowerCase()) reasons.push('PROOF_HASH_MISMATCH');
  }
  return {verified:reasons.length===0,reasons:[...new Set(reasons)].sort()};
}
function deriveManualEvidence({records={},target_amount_in_minor=29490000,now=new Date()}={}){
  const out={}; for(const kind of KINDS) out[kind]=validateEvidence(records[kind],{kind,now});
  const account=records.CURRENT_ACCOUNT?.proof_payload||{};
  const funds=records.AVAILABLE_FUNDS?.proof_payload||{};
  const limit=records.SINGLE_PAYMENT_LIMIT?.proof_payload||{};
  const sca=records.SCA_PATH?.proof_payload||{};
  return {
    schema:'atlas-revolut-manual-evidence-v1', rail_id:RAIL_ID, provider:PROVIDER,
    current_account_evidence_verified:out.CURRENT_ACCOUNT.verified&&account.account_status_current===true,
    available_funds_verified:out.AVAILABLE_FUNDS.verified&&Number.isSafeInteger(funds.available_funds_in_minor),
    available_funds_sufficient:out.AVAILABLE_FUNDS.verified&&Number(funds.available_funds_in_minor)>=target_amount_in_minor,
    bank_limit_verified:out.SINGLE_PAYMENT_LIMIT.verified&&Number.isSafeInteger(limit.max_single_payment_in_minor),
    amount_covered:out.SINGLE_PAYMENT_LIMIT.verified&&Number(limit.max_single_payment_in_minor)>=target_amount_in_minor,
    sca_path_verified:out.SCA_PATH.verified&&sca.user_app_approval_verified===true,
    target_amount_in_minor, validation:out,
    payment_endpoint_call_permitted:false, value_moved:false
  };
}
function template(kind,{observed_at=new Date().toISOString(),ttl_minutes=15}={}){
  if(!KINDS.includes(kind)) throw new Error('evidence_kind_invalid');
  const expires_at=new Date(Date.parse(observed_at)+ttl_minutes*60000).toISOString();
  return {probe_verified:false,source_reference:'',proof_sha256:'',proof_payload:{rail_id:RAIL_ID,provider:PROVIDER,evidence_kind:kind,source_type:'',probe_verified:false,observed_at,expires_at,account_reference_masked:'REVO-••••'}};
}
if(require.main===module){const kind=process.argv[2]||'CURRENT_ACCOUNT';console.log(JSON.stringify(template(kind),null,2));}
module.exports={RAIL_ID,PROVIDER,KINDS,SOURCE_TYPES,stable,sha256Object,validateEvidence,deriveManualEvidence,template};
