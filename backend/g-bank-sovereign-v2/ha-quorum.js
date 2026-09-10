'use strict';

const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('./canonical');

function positiveInt(name, value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 1) throw new Error(`${name}_invalid`);
  return n;
}

function hash64(name, value, { nullable = false } = {}) {
  if (nullable && value === null) return null;
  const v = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) throw new Error(`${name}_invalid`);
  return v;
}

function normalizeCluster(config) {
  if (!config || typeof config !== 'object') throw new Error('ha_cluster_required');
  const clusterId = String(config.cluster_id || '').toUpperCase();
  if (!/^[A-Z0-9:_-]{3,96}$/.test(clusterId)) throw new Error('ha_cluster_id_invalid');
  const clusterEpoch = positiveInt('ha_cluster_epoch', config.cluster_epoch);
  if (!Array.isArray(config.nodes) || config.nodes.length < 3 || config.nodes.length > 9) throw new Error('ha_cluster_nodes_invalid');

  const seen = new Set();
  const nodes = config.nodes.map(node => {
    const nodeId = String(node?.node_id || '').toUpperCase();
    if (!/^[A-Z0-9:_-]{3,96}$/.test(nodeId) || seen.has(nodeId)) throw new Error('ha_node_id_invalid_or_duplicate');
    seen.add(nodeId);
    const role = String(node?.role || 'VOTER').toUpperCase();
    if (!['VOTER', 'LEARNER'].includes(role)) throw new Error('ha_node_role_invalid');
    const status = String(node?.status || 'ACTIVE').toUpperCase();
    if (!['ACTIVE', 'REVOKED'].includes(status)) throw new Error('ha_node_status_invalid');
    const publicKeyPem = String(node?.public_key_pem || '');
    if (!publicKeyPem.includes('BEGIN PUBLIC KEY')) throw new Error('ha_node_public_key_required');
    let key;
    try { key = crypto.createPublicKey(publicKeyPem); } catch { throw new Error('ha_node_public_key_invalid'); }
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('ha_node_key_type_must_be_ed25519');
    return Object.freeze({
      node_id: nodeId,
      role,
      status,
      public_key_pem: publicKeyPem,
      public_key_binding_sha256: sha256(key.export({ type: 'spki', format: 'der' })),
    });
  }).sort((a, b) => a.node_id.localeCompare(b.node_id));

  const activeVoters = nodes.filter(node => node.role === 'VOTER' && node.status === 'ACTIVE');
  if (activeVoters.length < 3) throw new Error('ha_active_voter_count_too_low');
  const quorum = Math.floor(activeVoters.length / 2) + 1;
  const body = {
    schema: 'g-bank-ha-cluster/v2',
    cluster_id: clusterId,
    cluster_epoch: clusterEpoch,
    nodes,
    active_voter_count: activeVoters.length,
    quorum,
  };
  return Object.freeze({ ...body, cluster_sha256: sha256(canonicalJson(body)) });
}

function proposal(body, schema) {
  const normalized = { schema, ...body };
  return Object.freeze({ ...normalized, proposal_sha256: sha256(canonicalJson(normalized)) });
}

function createFenceProposal({ cluster, term, leader_node_id, previous_fence_sha256 = null, valid_from, valid_until }) {
  const c = normalizeCluster(cluster);
  const leader = String(leader_node_id || '').toUpperCase();
  const node = c.nodes.find(n => n.node_id === leader && n.role === 'VOTER' && n.status === 'ACTIVE');
  if (!node) throw new Error('ha_fence_leader_not_active_voter');
  const start = Date.parse(valid_from);
  const end = Date.parse(valid_until);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || end - start > 300000) throw new Error('ha_fence_window_invalid');
  return proposal({
    cluster_sha256: c.cluster_sha256,
    cluster_epoch: c.cluster_epoch,
    term: positiveInt('ha_fence_term', term),
    leader_node_id: leader,
    previous_fence_sha256: hash64('ha_previous_fence_sha256', previous_fence_sha256, { nullable: true }),
    valid_from: new Date(start).toISOString(),
    valid_until: new Date(end).toISOString(),
  }, 'g-bank-ha-fence-proposal/v2');
}

function createCommitProposal({ cluster, term, leader_node_id, commit_index, state_root_sha256, fence_record_sha256, previous_commit_sha256 = null }) {
  const c = normalizeCluster(cluster);
  const leader = String(leader_node_id || '').toUpperCase();
  const node = c.nodes.find(n => n.node_id === leader && n.role === 'VOTER' && n.status === 'ACTIVE');
  if (!node) throw new Error('ha_commit_leader_not_active_voter');
  return proposal({
    cluster_sha256: c.cluster_sha256,
    cluster_epoch: c.cluster_epoch,
    term: positiveInt('ha_commit_term', term),
    leader_node_id: leader,
    commit_index: positiveInt('ha_commit_index', commit_index),
    state_root_sha256: hash64('ha_state_root_sha256', state_root_sha256),
    fence_record_sha256: hash64('ha_fence_record_sha256', fence_record_sha256),
    previous_commit_sha256: hash64('ha_previous_commit_sha256', previous_commit_sha256, { nullable: true }),
  }, 'g-bank-ha-commit-proposal/v2');
}

function signatureEnvelope({ proposal: p, node_id, signed_at, signer_key_binding_sha256 }) {
  if (!p || !/^g-bank-ha-(fence|commit)-proposal\/v2$/.test(String(p.schema || ''))) throw new Error('ha_proposal_invalid');
  const nodeId = String(node_id || '').toUpperCase();
  if (!/^[A-Z0-9:_-]{3,96}$/.test(nodeId)) throw new Error('ha_signature_node_id_invalid');
  const signedAt = Date.parse(signed_at);
  if (!Number.isFinite(signedAt)) throw new Error('ha_signature_time_invalid');
  return Object.freeze({
    schema: 'g-bank-ha-signature-envelope/v2',
    node_id: nodeId,
    cluster_sha256: hash64('ha_signature_cluster_sha256', p.cluster_sha256),
    cluster_epoch: positiveInt('ha_signature_cluster_epoch', p.cluster_epoch),
    proposal_schema: p.schema,
    proposal_sha256: hash64('ha_signature_proposal_sha256', p.proposal_sha256),
    signer_key_binding_sha256: hash64('ha_signer_key_binding_sha256', signer_key_binding_sha256),
    signed_at: new Date(signedAt).toISOString(),
  });
}

function privateKeyBinding(privateKey) {
  let publicKey;
  try { publicKey = crypto.createPublicKey(privateKey); } catch { throw new Error('ha_private_key_invalid'); }
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('ha_private_key_type_must_be_ed25519');
  return sha256(publicKey.export({ type: 'spki', format: 'der' }));
}

function signProposal({ proposal: p, node_id, private_key, signed_at = new Date().toISOString(), vote_store = null }) {
  if (!p?.proposal_sha256) throw new Error('ha_proposal_required');
  const nodeId = String(node_id || '').toUpperCase();
  const keyBinding = privateKeyBinding(private_key);
  const envelope = signatureEnvelope({ proposal: p, node_id: nodeId, signed_at, signer_key_binding_sha256: keyBinding });
  const payload = canonicalJson(envelope);
  const signedPayloadSha256 = sha256(payload);
  if (vote_store) {
    if (typeof vote_store.reserve !== 'function') throw new Error('ha_vote_store_invalid');
    vote_store.reserve({ proposal: p, node_id: nodeId, signer_key_binding_sha256: keyBinding, signed_at: envelope.signed_at });
  }
  const signature = crypto.sign(null, Buffer.from(payload, 'utf8'), private_key).toString('base64');
  return Object.freeze({
    ...envelope,
    signed_payload_sha256: signedPayloadSha256,
    signature_base64: signature,
  });
}

function verifyProposal(p, c) {
  if (!p || !/^g-bank-ha-(fence|commit)-proposal\/v2$/.test(String(p.schema || ''))) throw new Error('ha_proposal_invalid');
  const { proposal_sha256, ...body } = p;
  if (sha256(canonicalJson(body)) !== String(proposal_sha256 || '').toLowerCase()) throw new Error('ha_proposal_hash_mismatch');
  if (p.cluster_sha256 !== c.cluster_sha256 || p.cluster_epoch !== c.cluster_epoch) throw new Error('ha_proposal_cluster_mismatch');
}

function verifyQuorumCertificate({ cluster, proposal: p, signatures, now = Date.now(), max_signature_age_ms = 300000 }) {
  const c = normalizeCluster(cluster);
  verifyProposal(p, c);
  if (!Array.isArray(signatures)) throw new Error('ha_signatures_required');

  const accepted = [];
  const seen = new Set();
  for (const sig of signatures) {
    const nodeId = String(sig?.node_id || '').toUpperCase();
    if (seen.has(nodeId)) throw new Error('ha_duplicate_signature');
    seen.add(nodeId);
    const node = c.nodes.find(n => n.node_id === nodeId && n.role === 'VOTER' && n.status === 'ACTIVE');
    if (!node) continue;
    const expectedEnvelope = signatureEnvelope({
      proposal: p,
      node_id: nodeId,
      signed_at: sig.signed_at,
      signer_key_binding_sha256: node.public_key_binding_sha256,
    });
    for (const [key, value] of Object.entries(expectedEnvelope)) {
      if (sig?.[key] !== value) throw new Error(`ha_signature_envelope_mismatch:${key}`);
    }
    const payload = canonicalJson(expectedEnvelope);
    if (hash64('ha_signed_payload_sha256', sig.signed_payload_sha256) !== sha256(payload)) throw new Error('ha_signature_payload_hash_mismatch');
    const signedAt = Date.parse(expectedEnvelope.signed_at);
    if (signedAt > now + 30000 || now - signedAt > max_signature_age_ms) throw new Error('ha_signature_stale_or_future');
    let ok = false;
    try {
      ok = crypto.verify(null, Buffer.from(payload, 'utf8'), node.public_key_pem, Buffer.from(String(sig.signature_base64 || ''), 'base64'));
    } catch { ok = false; }
    if (!ok) throw new Error('ha_signature_invalid');
    accepted.push(Object.freeze({
      ...expectedEnvelope,
      signed_payload_sha256: sig.signed_payload_sha256,
      signature_base64: String(sig.signature_base64),
    }));
  }
  accepted.sort((a, b) => a.node_id.localeCompare(b.node_id));
  if (accepted.length < c.quorum) throw new Error('ha_quorum_not_met');
  const certBody = {
    schema: 'g-bank-ha-quorum-certificate/v2',
    cluster_sha256: c.cluster_sha256,
    cluster_epoch: c.cluster_epoch,
    proposal_sha256: p.proposal_sha256,
    proposal_schema: p.schema,
    quorum_required: c.quorum,
    signer_node_ids: accepted.map(sig => sig.node_id),
    signatures: accepted,
    verified_at: new Date(now).toISOString(),
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
  };
  return Object.freeze({ ...certBody, certificate_sha256: sha256(canonicalJson(certBody)) });
}

function verifyStoredQuorumCertificate({ cluster, proposal: p, certificate }) {
  if (!certificate || certificate.schema !== 'g-bank-ha-quorum-certificate/v2') throw new Error('ha_stored_certificate_required');
  const supplied = hash64('ha_certificate_sha256', certificate.certificate_sha256);
  const { certificate_sha256, ...body } = certificate;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('ha_certificate_hash_mismatch');
  if (certificate.grants_external_rights !== false || certificate.permits_value_movement_by_itself !== false) throw new Error('ha_certificate_boundary_invalid');
  const verifiedAt = Date.parse(certificate.verified_at);
  if (!Number.isFinite(verifiedAt)) throw new Error('ha_certificate_verified_at_invalid');
  const reconstructed = verifyQuorumCertificate({ cluster, proposal: p, signatures: certificate.signatures, now: verifiedAt });
  if (reconstructed.certificate_sha256 !== supplied) throw new Error('ha_certificate_reverification_mismatch');
  return true;
}

module.exports = {
  normalizeCluster,
  createFenceProposal,
  createCommitProposal,
  signatureEnvelope,
  signProposal,
  verifyQuorumCertificate,
  verifyStoredQuorumCertificate,
};
