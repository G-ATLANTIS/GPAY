'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { deploymentObservationPayload, verifyHADeploymentObservation } = require('../g-bank-sovereign-v2/ha-deployment-attestation');

const NOW = Date.parse('2026-09-10T10:15:00.000Z');
const H = c => c.repeat(64);

function publicNode(id) {
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  return { node_id: id, role: 'VOTER', status: 'ACTIVE', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString() };
}

function fixture() {
  const cluster = { cluster_id: 'G-BANK-HA-PRIMARY', cluster_epoch: 1, nodes: [publicNode('NODE:A'), publicNode('NODE:B'), publicNode('NODE:C')] };
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const trustedObserver = { observer_id: 'OBSERVER:PRIMARY', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString() };
  const nodes = [
    { node_id: 'NODE:A', healthy: true, machine_identity_sha256: H('1'), endpoint_binding_sha256: H('2'), failure_domain_sha256: H('3'), boot_session_sha256: H('4'), healthcheck_receipt_sha256: H('5') },
    { node_id: 'NODE:B', healthy: true, machine_identity_sha256: H('6'), endpoint_binding_sha256: H('7'), failure_domain_sha256: H('8'), boot_session_sha256: H('9'), healthcheck_receipt_sha256: H('a') },
    { node_id: 'NODE:C', healthy: true, machine_identity_sha256: H('b'), endpoint_binding_sha256: H('c'), failure_domain_sha256: H('d'), boot_session_sha256: H('e'), healthcheck_receipt_sha256: H('f') },
  ];
  return { cluster, trustedObserver, privateKey, nodes };
}

function signedObservation(f, overrides = {}) {
  const payload = deploymentObservationPayload({
    cluster: f.cluster,
    observer: f.trustedObserver,
    observed_at: new Date(NOW).toISOString(),
    nonce_sha256: H('0'),
    nodes: f.nodes,
    ...overrides,
  });
  return Object.freeze({
    ...payload,
    signature_base64: crypto.sign(null, Buffer.from(payload.observation_sha256, 'utf8'), f.privateKey).toString('base64'),
  });
}

(() => {
  const f = fixture();
  const observation = signedObservation(f);
  const audit = verifyHADeploymentObservation({ cluster: f.cluster, observation, trustedObserver: f.trustedObserver, now: NOW + 1000 });
  assert.equal(audit.state, 'PASS');
  assert.equal(audit.distributed_network_verified, true);
  assert.equal(audit.active_voter_count, 3);
  assert.equal(audit.observed_active_voter_count, 3);
  assert.equal(audit.unique_failure_domains_verified, true);
  assert.equal(audit.grants_external_rights, false);
  assert.equal(audit.permits_value_movement_by_itself, false);
  assert.match(audit.audit_sha256, /^[0-9a-f]{64}$/);
})();

(() => {
  const f = fixture();
  const observation = { ...signedObservation(f), signature_base64: Buffer.from('forged').toString('base64') };
  assert.throws(() => verifyHADeploymentObservation({ cluster: f.cluster, observation, trustedObserver: f.trustedObserver, now: NOW + 1000 }), /ha_deployment_observer_signature_invalid/);
})();

(() => {
  const f = fixture();
  const badNodes = f.nodes.map(node => ({ ...node }));
  badNodes[2].failure_domain_sha256 = badNodes[1].failure_domain_sha256;
  const observation = signedObservation(f, { nodes: badNodes });
  assert.throws(() => verifyHADeploymentObservation({ cluster: f.cluster, observation, trustedObserver: f.trustedObserver, now: NOW + 1000 }), /ha_deployment_failure_domain_not_unique/);
})();

(() => {
  const f = fixture();
  const observation = signedObservation(f, { nodes: f.nodes.slice(0, 2) });
  assert.throws(() => verifyHADeploymentObservation({ cluster: f.cluster, observation, trustedObserver: f.trustedObserver, now: NOW + 1000 }), /ha_deployment_all_active_voters_required/);
})();

(() => {
  const f = fixture();
  const observation = signedObservation(f, { observed_at: new Date(NOW - 61000).toISOString() });
  assert.throws(() => verifyHADeploymentObservation({ cluster: f.cluster, observation, trustedObserver: f.trustedObserver, now: NOW }), /ha_deployment_observation_stale_or_future/);
})();

(() => {
  const f = fixture();
  const other = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const observation = signedObservation(f);
  assert.throws(() => verifyHADeploymentObservation({ cluster: f.cluster, observation, trustedObserver: { observer_id: 'OBSERVER:PRIMARY', public_key_pem: other }, now: NOW + 1000 }), /ha_deployment_observer_mismatch/);
})();

console.log('G-BANK sovereign v2 HA deployment attestation tests: PASS');
