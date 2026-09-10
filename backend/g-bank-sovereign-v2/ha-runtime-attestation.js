'use strict';

const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('./canonical');
const { normalizeObserver } = require('./ha-deployment-attestation');

function hash64(name, value) {
  const v = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) throw new Error(`${name}_invalid`);
  return v;
}

function positiveInt(name, value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 1) throw new Error(`${name}_invalid`);
  return n;
}

function verifyAssessment(value, schema, hashField) {
  if (!value || value.schema !== schema || value.state !== 'PASS') throw new Error(`${schema}_pass_required`);
  const supplied = hash64(hashField, value[hashField]);
  const copy = { ...value }; delete copy[hashField];
  if (sha256(canonicalJson(copy)) !== supplied) throw new Error(`${hashField}_mismatch`);
  return supplied;
}

function runtimeHAObservationPayload({ haAudit, haDeploymentAudit, observer, observed_at, nonce_sha256, operation_binding_sha256 }) {
  const o = normalizeObserver(observer);
  const haAuditSha = verifyAssessment(haAudit, 'g-bank-ha-readiness-audit/v2', 'audit_sha256');
  const deploymentAuditSha = verifyAssessment(haDeploymentAudit, 'g-bank-ha-deployment-audit/v2', 'audit_sha256');
  if (haDeploymentAudit.cluster_sha256 !== haAudit.cluster_sha256 || haDeploymentAudit.cluster_epoch !== haAudit.cluster_epoch) throw new Error('ha_runtime_deployment_cluster_mismatch');
  const observed = Date.parse(observed_at);
  if (!Number.isFinite(observed)) throw new Error('ha_runtime_observed_at_invalid');
  const fenceExpiry = Date.parse(haAudit.fence_valid_until);
  if (!Number.isFinite(fenceExpiry)) throw new Error('ha_runtime_fence_valid_until_invalid');

  const body = {
    schema: 'g-bank-ha-runtime-observation/v2',
    cluster_sha256: hash64('ha_runtime_cluster_sha256', haAudit.cluster_sha256),
    cluster_epoch: positiveInt('ha_runtime_cluster_epoch', haAudit.cluster_epoch),
    cluster_authority_root_sha256: hash64('ha_runtime_cluster_authority_root_sha256', haAudit.cluster_authority_root_sha256),
    voter_journal_root_sha256: hash64('ha_runtime_voter_journal_root_sha256', haAudit.voter_journal_root_sha256),
    fence_record_sha256: hash64('ha_runtime_fence_record_sha256', haAudit.fence_record_sha256),
    fence_valid_until: new Date(fenceExpiry).toISOString(),
    latest_commit_index: positiveInt('ha_runtime_latest_commit_index', haAudit.latest_commit_index),
    latest_commit_sha256: hash64('ha_runtime_latest_commit_sha256', haAudit.latest_commit_sha256),
    state_root_sha256: hash64('ha_runtime_state_root_sha256', haAudit.checkpoint_state_root_sha256),
    ha_audit_sha256: haAuditSha,
    ha_deployment_audit_sha256: deploymentAuditSha,
    observer_id: o.observer_id,
    observer_public_key_binding_sha256: o.public_key_binding_sha256,
    observed_at: new Date(observed).toISOString(),
    nonce_sha256: hash64('ha_runtime_nonce_sha256', nonce_sha256),
    operation_binding_sha256: hash64('ha_runtime_operation_binding_sha256', operation_binding_sha256),
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
  };
  return Object.freeze({ ...body, observation_sha256: sha256(canonicalJson(body)) });
}

function signHARuntimeObservation({ payload, private_key }) {
  if (!payload || payload.schema !== 'g-bank-ha-runtime-observation/v2') throw new Error('ha_runtime_payload_required');
  let publicKey;
  try { publicKey = crypto.createPublicKey(private_key); } catch { throw new Error('ha_runtime_private_key_invalid'); }
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('ha_runtime_private_key_type_must_be_ed25519');
  const binding = sha256(publicKey.export({ type: 'spki', format: 'der' }));
  if (binding !== payload.observer_public_key_binding_sha256) throw new Error('ha_runtime_private_key_binding_mismatch');
  const signature = crypto.sign(null, Buffer.from(payload.observation_sha256, 'utf8'), private_key).toString('base64');
  return Object.freeze({ ...payload, signature_base64: signature });
}

function verifyHARuntimeObservation({ observation, trustedObserver, expected, now = Date.now(), max_age_ms = 15000 } = {}) {
  const observer = normalizeObserver(trustedObserver);
  if (!observation || observation.schema !== 'g-bank-ha-runtime-observation/v2') throw new Error('ha_runtime_observation_required');
  const signature = String(observation.signature_base64 || '');
  const supplied = hash64('ha_runtime_observation_sha256', observation.observation_sha256);
  const { observation_sha256, signature_base64, ...body } = observation;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('ha_runtime_observation_hash_mismatch');
  if (observation.observer_id !== observer.observer_id || observation.observer_public_key_binding_sha256 !== observer.public_key_binding_sha256) throw new Error('ha_runtime_observer_mismatch');
  if (observation.grants_external_rights !== false || observation.permits_value_movement_by_itself !== false) throw new Error('ha_runtime_boundary_invalid');
  const observedAt = Date.parse(observation.observed_at);
  if (!Number.isFinite(observedAt) || observedAt > now + 5000 || now - observedAt > max_age_ms) throw new Error('ha_runtime_observation_stale_or_future');
  const fenceExpiry = Date.parse(observation.fence_valid_until);
  if (!Number.isFinite(fenceExpiry) || fenceExpiry <= now) throw new Error('ha_runtime_fence_expired');
  let signatureValid = false;
  try { signatureValid = crypto.verify(null, Buffer.from(supplied, 'utf8'), observer.public_key_pem, Buffer.from(signature, 'base64')); } catch { signatureValid = false; }
  if (!signatureValid) throw new Error('ha_runtime_observer_signature_invalid');

  const fields = [
    'cluster_authority_root_sha256', 'voter_journal_root_sha256', 'state_root_sha256',
    'ha_audit_sha256', 'ha_deployment_audit_sha256', 'operation_binding_sha256', 'observer_public_key_binding_sha256',
  ];
  for (const field of fields) {
    const actual = hash64(`ha_runtime_${field}`, observation[field]);
    const wanted = hash64(`ha_runtime_expected_${field}`, expected?.[field]);
    if (actual !== wanted) throw new Error(`ha_runtime_expected_mismatch:${field}`);
  }
  if (String(observation.fence_valid_until) !== String(expected?.fence_valid_until || '')) throw new Error('ha_runtime_expected_mismatch:fence_valid_until');

  const auditBody = {
    schema: 'g-bank-ha-runtime-attestation-audit/v2',
    state: 'PASS',
    observation_sha256: supplied,
    observer_id: observer.observer_id,
    observer_public_key_binding_sha256: observer.public_key_binding_sha256,
    cluster_sha256: observation.cluster_sha256,
    cluster_epoch: observation.cluster_epoch,
    cluster_authority_root_sha256: observation.cluster_authority_root_sha256,
    voter_journal_root_sha256: observation.voter_journal_root_sha256,
    fence_record_sha256: observation.fence_record_sha256,
    fence_valid_until: observation.fence_valid_until,
    latest_commit_index: observation.latest_commit_index,
    latest_commit_sha256: observation.latest_commit_sha256,
    state_root_sha256: observation.state_root_sha256,
    ha_audit_sha256: observation.ha_audit_sha256,
    ha_deployment_audit_sha256: observation.ha_deployment_audit_sha256,
    operation_binding_sha256: observation.operation_binding_sha256,
    observed_at: observation.observed_at,
    verified_at: new Date(now).toISOString(),
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
  };
  return Object.freeze({ ...auditBody, audit_sha256: sha256(canonicalJson(auditBody)) });
}

module.exports = { runtimeHAObservationPayload, signHARuntimeObservation, verifyHARuntimeObservation, verifyAssessment };
