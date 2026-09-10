'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { runtimeHAObservationPayload, signHARuntimeObservation, verifyHARuntimeObservation } = require('../g-bank-sovereign-v2/ha-runtime-attestation');

const NOW = Date.parse('2026-09-10T11:15:00.000Z');
const H = c => c.repeat(64);

function hashed(schema, hashField, extra = {}) {
  const body = { schema, state: 'PASS', ...extra };
  return Object.freeze({ ...body, [hashField]: sha256(canonicalJson(body)) });
}

function fixture() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const observerBinding = sha256(publicKey.export({ type: 'spki', format: 'der' }));
  const observer = { observer_id: 'OBSERVER:RUNTIME:PRIMARY', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString() };
  const haAudit = hashed('g-bank-ha-readiness-audit/v2', 'audit_sha256', {
    cluster_sha256: H('1'), cluster_epoch: 2, cluster_authority_root_sha256: H('2'), voter_journal_root_sha256: H('3'),
    fence_record_sha256: H('4'), fence_valid_until: new Date(NOW + 60000).toISOString(), latest_commit_index: 77,
    latest_commit_sha256: H('5'), checkpoint_state_root_sha256: H('6'), reasons: [], grants_external_rights: false, permits_value_movement_by_itself: false,
  });
  const deploymentAudit = hashed('g-bank-ha-deployment-audit/v2', 'audit_sha256', {
    cluster_sha256: H('1'), cluster_epoch: 2, observer_id: 'OBSERVER:DEPLOYMENT', distributed_network_verified: true,
    grants_external_rights: false, permits_value_movement_by_itself: false,
  });
  const payload = runtimeHAObservationPayload({ haAudit, haDeploymentAudit: deploymentAudit, observer, observed_at: new Date(NOW).toISOString(), nonce_sha256: H('7'), operation_binding_sha256: H('8') });
  const observation = signHARuntimeObservation({ payload, private_key: privateKey });
  const expected = {
    cluster_authority_root_sha256: H('2'), voter_journal_root_sha256: H('3'), state_root_sha256: H('6'),
    ha_audit_sha256: haAudit.audit_sha256, ha_deployment_audit_sha256: deploymentAudit.audit_sha256,
    operation_binding_sha256: H('8'), observer_public_key_binding_sha256: observerBinding,
    fence_valid_until: new Date(NOW + 60000).toISOString(),
  };
  return { observer, observerBinding, privateKey, haAudit, deploymentAudit, payload, observation, expected };
}

(() => {
  const f = fixture();
  const audit = verifyHARuntimeObservation({ observation: f.observation, trustedObserver: f.observer, expected: f.expected, now: NOW + 1000 });
  assert.equal(audit.state, 'PASS');
  assert.equal(audit.observer_public_key_binding_sha256, f.observerBinding);
  assert.equal(audit.operation_binding_sha256, H('8'));
  assert.match(audit.audit_sha256, /^[0-9a-f]{64}$/);
})();

(() => {
  const f = fixture();
  for (const [field, value] of [
    ['cluster_authority_root_sha256', H('9')], ['voter_journal_root_sha256', H('9')], ['ha_audit_sha256', H('9')],
    ['operation_binding_sha256', H('9')], ['observer_public_key_binding_sha256', H('9')],
  ]) assert.throws(() => verifyHARuntimeObservation({ observation: f.observation, trustedObserver: f.observer, expected: { ...f.expected, [field]: value }, now: NOW + 1000 }), new RegExp(`ha_runtime_expected_mismatch:${field}`));
})();

(() => {
  const f = fixture();
  const forged = { ...f.observation, signature_base64: Buffer.from('forged').toString('base64') };
  assert.throws(() => verifyHARuntimeObservation({ observation: forged, trustedObserver: f.observer, expected: f.expected, now: NOW + 1000 }), /ha_runtime_observer_signature_invalid/);
})();

(() => {
  const f = fixture();
  assert.throws(() => verifyHARuntimeObservation({ observation: f.observation, trustedObserver: f.observer, expected: f.expected, now: NOW + 16000 }), /ha_runtime_observation_stale_or_future/);
  assert.throws(() => verifyHARuntimeObservation({ observation: f.observation, trustedObserver: f.observer, expected: f.expected, now: NOW + 60000 }), /ha_runtime_observation_stale_or_future|ha_runtime_fence_expired/);
})();

(() => {
  const f = fixture();
  const tampered = { ...f.observation, operation_binding_sha256: H('9') };
  assert.throws(() => verifyHARuntimeObservation({ observation: tampered, trustedObserver: f.observer, expected: f.expected, now: NOW + 1000 }), /ha_runtime_observation_hash_mismatch/);
})();

console.log('G-BANK sovereign v2 promotion-pinned transaction-bound HA attestation tests: PASS');
