'use strict';

const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('./canonical');
const { normalizeCluster } = require('./ha-quorum');

function hash64(name, value) {
  const v = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) throw new Error(`${name}_invalid`);
  return v;
}

function normalizeObserver(observer) {
  const observerId = String(observer?.observer_id || '').toUpperCase();
  if (!/^[A-Z0-9:_-]{3,96}$/.test(observerId)) throw new Error('ha_observer_id_invalid');
  const publicKeyPem = String(observer?.public_key_pem || '');
  let key;
  try { key = crypto.createPublicKey(publicKeyPem); } catch { throw new Error('ha_observer_public_key_invalid'); }
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('ha_observer_key_type_must_be_ed25519');
  return Object.freeze({
    observer_id: observerId,
    public_key_pem: publicKeyPem,
    public_key_binding_sha256: sha256(key.export({ type: 'spki', format: 'der' })),
  });
}

function deploymentObservationPayload({ cluster, observer, observed_at, nonce_sha256, nodes }) {
  const c = normalizeCluster(cluster);
  const o = normalizeObserver(observer);
  const observed = Date.parse(observed_at);
  if (!Number.isFinite(observed)) throw new Error('ha_deployment_observed_at_invalid');
  if (!Array.isArray(nodes) || !nodes.length) throw new Error('ha_deployment_nodes_required');
  const seen = new Set();
  const normalizedNodes = nodes.map(row => {
    const nodeId = String(row?.node_id || '').toUpperCase();
    if (seen.has(nodeId)) throw new Error('ha_deployment_duplicate_node');
    seen.add(nodeId);
    return Object.freeze({
      node_id: nodeId,
      healthy: row?.healthy === true,
      machine_identity_sha256: hash64('ha_machine_identity_sha256', row?.machine_identity_sha256),
      endpoint_binding_sha256: hash64('ha_endpoint_binding_sha256', row?.endpoint_binding_sha256),
      failure_domain_sha256: hash64('ha_failure_domain_sha256', row?.failure_domain_sha256),
      boot_session_sha256: hash64('ha_boot_session_sha256', row?.boot_session_sha256),
      healthcheck_receipt_sha256: hash64('ha_healthcheck_receipt_sha256', row?.healthcheck_receipt_sha256),
    });
  }).sort((a, b) => a.node_id.localeCompare(b.node_id));
  const body = {
    schema: 'g-bank-ha-deployment-observation/v2',
    cluster_sha256: c.cluster_sha256,
    cluster_epoch: c.cluster_epoch,
    observer_id: o.observer_id,
    observer_public_key_binding_sha256: o.public_key_binding_sha256,
    observed_at: new Date(observed).toISOString(),
    nonce_sha256: hash64('ha_deployment_nonce_sha256', nonce_sha256),
    nodes: normalizedNodes,
  };
  return Object.freeze({ ...body, observation_sha256: sha256(canonicalJson(body)) });
}

function verifyHADeploymentObservation({ cluster, observation, trustedObserver, now = Date.now(), max_age_ms = 60000 } = {}) {
  const c = normalizeCluster(cluster);
  const observer = normalizeObserver(trustedObserver);
  if (!observation || observation.schema !== 'g-bank-ha-deployment-observation/v2') throw new Error('ha_deployment_observation_required');
  const supplied = hash64('ha_deployment_observation_sha256', observation.observation_sha256);
  const signature = String(observation.signature_base64 || '');
  const { observation_sha256, signature_base64, ...body } = observation;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('ha_deployment_observation_hash_mismatch');
  if (observation.cluster_sha256 !== c.cluster_sha256 || observation.cluster_epoch !== c.cluster_epoch) throw new Error('ha_deployment_cluster_mismatch');
  if (observation.observer_id !== observer.observer_id || observation.observer_public_key_binding_sha256 !== observer.public_key_binding_sha256) throw new Error('ha_deployment_observer_mismatch');
  const observedAt = Date.parse(observation.observed_at);
  if (!Number.isFinite(observedAt) || observedAt > now + 30000 || now - observedAt > max_age_ms) throw new Error('ha_deployment_observation_stale_or_future');
  let signatureValid = false;
  try { signatureValid = crypto.verify(null, Buffer.from(supplied, 'utf8'), observer.public_key_pem, Buffer.from(signature, 'base64')); } catch { signatureValid = false; }
  if (!signatureValid) throw new Error('ha_deployment_observer_signature_invalid');

  const activeVoters = c.nodes.filter(node => node.role === 'VOTER' && node.status === 'ACTIVE').map(node => node.node_id).sort();
  const observedNodes = Array.isArray(observation.nodes) ? observation.nodes : [];
  if (observedNodes.length !== activeVoters.length) throw new Error('ha_deployment_all_active_voters_required');
  const observedIds = observedNodes.map(node => String(node.node_id || '').toUpperCase()).sort();
  if (observedIds.join('|') !== activeVoters.join('|')) throw new Error('ha_deployment_active_voter_set_mismatch');
  if (observedNodes.some(node => node.healthy !== true)) throw new Error('ha_deployment_unhealthy_node');

  for (const [field, errorName] of [
    ['machine_identity_sha256', 'ha_deployment_machine_identity_not_unique'],
    ['endpoint_binding_sha256', 'ha_deployment_endpoint_not_unique'],
    ['failure_domain_sha256', 'ha_deployment_failure_domain_not_unique'],
    ['boot_session_sha256', 'ha_deployment_boot_session_not_unique'],
    ['healthcheck_receipt_sha256', 'ha_deployment_healthcheck_receipt_not_unique'],
  ]) {
    const values = observedNodes.map(node => hash64(`ha_deployment_${field}`, node[field]));
    if (new Set(values).size !== values.length) throw new Error(errorName);
  }

  const auditBody = {
    schema: 'g-bank-ha-deployment-audit/v2',
    state: 'PASS',
    cluster_sha256: c.cluster_sha256,
    cluster_epoch: c.cluster_epoch,
    active_voter_count: activeVoters.length,
    observed_active_voter_count: observedNodes.length,
    observer_id: observer.observer_id,
    observer_public_key_binding_sha256: observer.public_key_binding_sha256,
    observation_sha256: supplied,
    observed_at: observation.observed_at,
    audited_at: new Date(now).toISOString(),
    distributed_network_verified: true,
    all_active_voters_healthy: true,
    unique_machine_identities_verified: true,
    unique_endpoints_verified: true,
    unique_failure_domains_verified: true,
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
  };
  return Object.freeze({ ...auditBody, audit_sha256: sha256(canonicalJson(auditBody)) });
}

module.exports = { normalizeObserver, deploymentObservationPayload, verifyHADeploymentObservation };
