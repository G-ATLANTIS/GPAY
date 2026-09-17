#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');

const RAILS = Object.freeze([
  { id:'bunq-native-draft', activation_rank:10, credential_env:['BUNQ_API_KEY'], production_env:['BUNQ_ENV=production'], external_gates:[], probe:'bunq-readonly-v1' },
  { id:'adyen-api', activation_rank:20, credential_env:['ADYEN_API_KEY','ADYEN_API_USERNAME','ADYEN_BALANCE_ACCOUNT_ID','ADYEN_LIVE_URL_PREFIX'], production_env:['ADYEN_ENV=production'], external_gates:['ADYEN_OUTBOUND_ONBOARDING_VERIFIED'], probe:'adyen-readonly-v1' },
  { id:'tink-open-banking', activation_rank:30, credential_env:['TINK_CLIENT_ID','TINK_CLIENT_SECRET'], production_env:['TINK_ENV=production'], external_gates:['TINK_PRODUCTION_ONBOARDING_VERIFIED'], probe:'tink-readonly-v1' },
  { id:'yapily-connect', activation_rank:40, credential_env:['YAPILY_APPLICATION_KEY','YAPILY_APPLICATION_SECRET'], production_env:['YAPILY_ENV=production'], external_gates:['YAPILY_CONNECT_APPROVED'], probe:'yapily-readonly-v1' },
  { id:'atlas-own-pisp', activation_rank:90, credential_env:[], production_env:['ATLAS_PISP_PRODUCTION=true'], external_gates:['ATLAS_PISP_DNB_AUTHORISED','ATLAS_PISP_EIDAS_READY','ATLAS_PISP_BANK_REGISTRATION_VERIFIED'], probe:'own-pisp-readonly-v1' },
  { id:'atlas-direct-sepa', activation_rank:100, credential_env:[], production_env:['ATLAS_DIRECT_SEPA_PRODUCTION=true'], external_gates:['ATLAS_DIRECT_SEPA_PSP_AUTHORIZATION_VERIFIED','ATLAS_DIRECT_SEPA_EPC_ADHERENCE_VERIFIED','ATLAS_DIRECT_SEPA_SETTLEMENT_ACCESS_VERIFIED','ATLAS_DIRECT_SEPA_NETWORK_ACCESS_VERIFIED','ATLAS_DIRECT_SEPA_HSM_VERIFIED','ATLAS_DIRECT_SEPA_VOP_VERIFIED'], probe:'direct-sepa-readonly-v1' }
]);

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, stable(value[k])]));
  return value;
}
function sha256Object(value) { return crypto.createHash('sha256').update(JSON.stringify(stable(value))).digest('hex'); }
function present(env, key) { return typeof env[key] === 'string' && env[key].trim().length > 0; }
function yes(env, key) { return String(env[key] || '').trim().toLowerCase() === 'true'; }
function productionSatisfied(env, expression) {
  const [key, expected] = expression.split('=');
  return String(env[key] || '').trim().toLowerCase() === expected.toLowerCase();
}
function validProof(item, now = new Date(), expectedRailId = null) {
  if (!item || item.probe_verified !== true) return false;
  if (!String(item.source_reference || '').trim()) return false;
  const payload = item.proof_payload;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return false;
  if (expectedRailId && payload.rail_id !== expectedRailId) return false;
  if (payload.probe_verified !== true) return false;
  if (!/^[0-9a-f]{64}$/i.test(String(item.proof_sha256 || ''))) return false;
  if (sha256Object(payload) !== String(item.proof_sha256).toLowerCase()) return false;
  const observed = Date.parse(payload.observed_at || '');
  const expires = Date.parse(payload.expires_at || '');
  const t = now.getTime();
  return Number.isFinite(observed) && Number.isFinite(expires) && observed <= t + 60000 && expires > t;
}
function evaluateRail(rail, {env = process.env, evidence = {}, now = new Date()} = {}) {
  const missingCredentials = rail.credential_env.filter(k => !present(env, k));
  const missingProduction = rail.production_env.filter(x => !productionSatisfied(env, x));
  const missingExternal = rail.external_gates.filter(k => !yes(env, k));
  const proof = evidence[rail.id];
  const readOnlyVerified = validProof(proof, now, rail.id);
  let state = 'READY_FOR_READONLY_PROBE';
  if (missingCredentials.length) state = 'BLOCKED_CREDENTIALS';
  else if (missingProduction.length) state = 'BLOCKED_PRODUCTION_CONFIG';
  else if (missingExternal.length) state = 'BLOCKED_EXTERNAL_ONBOARDING';
  else if (readOnlyVerified) state = 'VERIFIED_READ_ONLY';
  return {
    rail_id: rail.id, activation_rank: rail.activation_rank, state,
    missing_credentials: missingCredentials,
    missing_production: missingProduction,
    missing_external_gates: missingExternal,
    probe_contract: rail.probe,
    read_only_verified: readOnlyVerified,
    proof_sha256: readOnlyVerified ? proof.proof_sha256 : null,
    source_reference: readOnlyVerified ? proof.source_reference : null,
    payment_write_enabled: false,
    provider_call_permitted: false,
    value_moved: false
  };
}
function activationMatrix({env = process.env, evidence = {}, now = new Date()} = {}) {
  const rails = RAILS.map(r => evaluateRail(r, {env,evidence,now})).sort((a,b)=>a.activation_rank-b.activation_rank);
  const verified = rails.filter(r => r.read_only_verified);
  const probeable = rails.filter(r => r.state === 'READY_FOR_READONLY_PROBE');
  const next = verified[0] || probeable[0] || rails[0] || null;
  return {
    schema:'atlas-payment-rail-activation-matrix-v1', generated_at:now.toISOString(),
    target:'FIRST_VERIFIED_READ_ONLY_RAIL', total_rails:rails.length,
    verified_read_only_count:verified.length,
    next_activation_rail_id:next?.rail_id || null,
    rails,
    payment_write_enabled:false, provider_call_permitted:false, value_moved:false
  };
}

if (require.main === module) console.log(JSON.stringify(activationMatrix(), null, 2));
module.exports = { RAILS, stable, sha256Object, validProof, evaluateRail, activationMatrix };
