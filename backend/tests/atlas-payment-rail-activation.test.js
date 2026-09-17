#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { activationMatrix, validProof } = require('../../scripts/atlas-payment-rail-activation');
const { probePlan } = require('../../scripts/atlas-payment-rail-probe-contracts');
const h = s => crypto.createHash('sha256').update(s).digest('hex');
const now = new Date('2026-09-17T13:45:00.000Z');

const empty = activationMatrix({env:{}, evidence:{}, now});
assert.equal(empty.total_rails, 6);
assert.equal(empty.verified_read_only_count, 0);
assert.equal(empty.next_activation_rail_id, 'bunq-native-draft');
assert.equal(empty.payment_write_enabled, false);
assert.equal(empty.provider_call_permitted, false);
assert.equal(empty.value_moved, false);

const bunqEnv = {BUNQ_API_KEY:'opaque', BUNQ_ENV:'production'};
const bunqReady = activationMatrix({env:bunqEnv, evidence:{}, now});
assert.equal(bunqReady.rails[0].state, 'READY_FOR_READONLY_PROBE');
assert.equal(probePlan({rail_id:'bunq-native-draft', env:bunqEnv, now}).can_run_readonly_network_probe, false);
assert.equal(probePlan({rail_id:'bunq-native-draft', env:{...bunqEnv,ATLAS_ALLOW_READONLY_NETWORK_PROBE:'true'}, now}).can_run_readonly_network_probe, true);

const proof = {probe_verified:true, proof_sha256:h('bunq-proof'), source_reference:'provider:request:123', observed_at:'2026-09-17T13:44:00Z', expires_at:'2026-09-17T14:00:00Z'};
assert.equal(validProof(proof, now), true);
const verified = activationMatrix({env:bunqEnv, evidence:{'bunq-native-draft':proof}, now});
assert.equal(verified.verified_read_only_count, 1);
assert.equal(verified.rails[0].state, 'VERIFIED_READ_ONLY');
assert.equal(verified.rails[0].payment_write_enabled, false);
assert.equal(verified.rails[0].provider_call_permitted, false);

const stale = {...proof, expires_at:'2026-09-17T13:40:00Z'};
assert.equal(validProof(stale, now), false);
const noSource = {...proof, source_reference:''};
assert.equal(validProof(noSource, now), false);
const badHash = {...proof, proof_sha256:'not-a-hash'};
assert.equal(validProof(badHash, now), false);

const adyenEnv = {ADYEN_API_KEY:'x',ADYEN_API_USERNAME:'u',ADYEN_BALANCE_ACCOUNT_ID:'b',ADYEN_LIVE_URL_PREFIX:'https://live.example',ADYEN_ENV:'production',ADYEN_OUTBOUND_ONBOARDING_VERIFIED:'true',ATLAS_ALLOW_READONLY_NETWORK_PROBE:'true'};
assert.equal(probePlan({rail_id:'adyen-api', env:adyenEnv, now}).can_run_readonly_network_probe, false);
console.log('atlas-payment-rail-activation: PASS');
