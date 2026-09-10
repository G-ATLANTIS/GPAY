'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { runtimeHAObservationPayload, signHARuntimeObservation } = require('../g-bank-sovereign-v2/ha-runtime-attestation');

function H(c) { return c.repeat(64); }

function hashed(schema, hashField, extra = {}) {
  const body = { schema, state: 'PASS', ...extra };
  return Object.freeze({ ...body, [hashField]: sha256(canonicalJson(body)) });
}

function configureSyntheticRuntimeHA({ root, env, state_root_sha256 = H('6'), cluster_authority_root_sha256 = H('a'), voter_journal_root_sha256 = H('b'), fence_valid_until, now }) {
  if (!root || !env || !Number.isFinite(Number(now))) throw new Error('synthetic_runtime_ha_fixture_invalid');
  const fenceUntil = new Date(fence_valid_until).toISOString();
  const haAudit = hashed('g-bank-ha-readiness-audit/v2', 'audit_sha256', {
    cluster_sha256: H('c'), cluster_epoch: 1, cluster_authority_root_sha256, cluster_transition_count: 0, cluster_transition_head_sha256: null,
    active_voter_count: 3, quorum: 2, latest_term: 1, leader_node_id: 'NODE:A', fence_record_sha256: H('d'),
    fence_valid_until: fenceUntil, latest_commit_index: 1, latest_commit_sha256: H('e'), replicated_state_root_sha256: state_root_sha256,
    checkpoint_state_root_sha256: state_root_sha256, voter_journal_store_count: 3,
    voter_journal_heads: { 'NODE:A': H('1'), 'NODE:B': H('2'), 'NODE:C': null }, voter_journal_root_sha256,
    durable_fence_signer_count: 2, durable_commit_signer_count: 2, reasons: [], audited_at: new Date(now).toISOString(),
    grants_external_rights: false, permits_value_movement_by_itself: false, distributed_network_verified: false,
  });
  const haDeploymentAudit = hashed('g-bank-ha-deployment-audit/v2', 'audit_sha256', {
    cluster_sha256: haAudit.cluster_sha256, cluster_epoch: haAudit.cluster_epoch, active_voter_count: 3, observed_active_voter_count: 3,
    observer_id: 'OBSERVER:DEPLOYMENT:TEST', observer_public_key_binding_sha256: H('3'), observation_sha256: H('4'),
    observed_at: new Date(now).toISOString(), audited_at: new Date(now).toISOString(), distributed_network_verified: true,
    all_active_voters_healthy: true, unique_machine_identities_verified: true, unique_endpoints_verified: true,
    unique_failure_domains_verified: true, grants_external_rights: false, permits_value_movement_by_itself: false,
  });

  env.G_BANK_HA_AUDIT_SHA256 = haAudit.audit_sha256;
  env.G_BANK_HA_DEPLOYMENT_AUDIT_SHA256 = haDeploymentAudit.audit_sha256;

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const observer = { observer_id: 'OBSERVER:RUNTIME:TEST', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString() };
  const payload = runtimeHAObservationPayload({ haAudit, haDeploymentAudit, observer, observed_at: new Date(now).toISOString(), nonce_sha256: H('5') });
  const observation = signHARuntimeObservation({ payload, private_key: privateKey });
  const observationPath = path.join(root, 'runtime-ha-attestation.json');
  const observerPath = path.join(root, 'runtime-ha-observer.json');
  fs.writeFileSync(observationPath, JSON.stringify(observation, null, 2) + '\n', { mode: 0o600 });
  fs.writeFileSync(observerPath, JSON.stringify(observer, null, 2) + '\n', { mode: 0o600 });
  env.G_BANK_RUNTIME_HA_ATTESTATION_FILE = observationPath;
  env.G_BANK_RUNTIME_HA_OBSERVER_FILE = observerPath;

  return Object.freeze({ haAudit, haDeploymentAudit, observation, observer, cluster_authority_root_sha256, voter_journal_root_sha256, fence_valid_until: fenceUntil });
}

module.exports = { configureSyntheticRuntimeHA, hashed };
