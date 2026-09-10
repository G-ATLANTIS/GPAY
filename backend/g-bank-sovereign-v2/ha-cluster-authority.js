'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');
const { normalizeCluster } = require('./ha-quorum');

function hash64(name, value, { nullable = false } = {}) {
  if (nullable && value === null) return null;
  const v = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) throw new Error(`${name}_invalid`);
  return v;
}

function positiveInt(name, value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 1) throw new Error(`${name}_invalid`);
  return n;
}

function nodeId(value) {
  const id = String(value || '').toUpperCase();
  if (!/^[A-Z0-9:_-]{3,96}$/.test(id)) throw new Error('ha_reconfiguration_node_id_invalid');
  return id;
}

function publicBindingFromPrivate(privateKey) {
  let publicKey;
  try { publicKey = crypto.createPublicKey(privateKey); }
  catch { throw new Error('ha_reconfiguration_private_key_invalid'); }
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('ha_reconfiguration_private_key_type_invalid');
  return sha256(publicKey.export({ type: 'spki', format: 'der' }));
}

function normalizeTransitionClusters(fromCluster, toCluster) {
  const from = normalizeCluster(fromCluster);
  const to = normalizeCluster(toCluster);
  if (to.cluster_id !== from.cluster_id) throw new Error('ha_reconfiguration_cluster_id_mismatch');
  if (to.cluster_epoch !== from.cluster_epoch + 1) throw new Error('ha_reconfiguration_next_epoch_required');
  return { from, to };
}

function createClusterReconfigurationProposal({
  from_cluster,
  to_cluster,
  active_fence,
  latest_commit,
  previous_transition_sha256 = null,
  proposed_at = new Date().toISOString(),
} = {}) {
  const { from, to } = normalizeTransitionClusters(from_cluster, to_cluster);
  if (!active_fence || active_fence.schema !== 'g-bank-ha-fence-record/v2') throw new Error('ha_reconfiguration_active_fence_required');
  if (!latest_commit || latest_commit.schema !== 'g-bank-ha-commit-record/v2') throw new Error('ha_reconfiguration_latest_commit_required');
  if (active_fence.cluster_sha256 !== from.cluster_sha256) throw new Error('ha_reconfiguration_fence_cluster_mismatch');
  if (latest_commit.cluster_sha256 !== from.cluster_sha256) throw new Error('ha_reconfiguration_commit_cluster_mismatch');
  if (latest_commit.term !== active_fence.term || latest_commit.leader_node_id !== active_fence.leader_node_id || latest_commit.fence_record_sha256 !== active_fence.record_sha256) {
    throw new Error('ha_reconfiguration_commit_not_on_active_fence');
  }
  const proposedAt = Date.parse(proposed_at);
  if (!Number.isFinite(proposedAt)) throw new Error('ha_reconfiguration_proposed_at_invalid');
  const body = {
    schema: 'g-bank-ha-cluster-reconfiguration-proposal/v2',
    cluster_id: from.cluster_id,
    from_cluster_sha256: from.cluster_sha256,
    from_cluster_epoch: from.cluster_epoch,
    to_cluster_sha256: to.cluster_sha256,
    to_cluster_epoch: to.cluster_epoch,
    active_fence_record_sha256: hash64('ha_reconfiguration_fence_record_sha256', active_fence.record_sha256),
    active_fence_term: positiveInt('ha_reconfiguration_fence_term', active_fence.term),
    active_leader_node_id: nodeId(active_fence.leader_node_id),
    latest_commit_sha256: hash64('ha_reconfiguration_commit_sha256', latest_commit.record_sha256),
    latest_commit_index: positiveInt('ha_reconfiguration_commit_index', latest_commit.commit_index),
    replicated_state_root_sha256: hash64('ha_reconfiguration_state_root_sha256', latest_commit.state_root_sha256),
    previous_transition_sha256: hash64('ha_previous_transition_sha256', previous_transition_sha256, { nullable: true }),
    proposed_at: new Date(proposedAt).toISOString(),
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
  };
  return Object.freeze({ ...body, proposal_sha256: sha256(canonicalJson(body)) });
}

function verifyReconfigurationProposal(proposal, fromCluster, toCluster) {
  const { from, to } = normalizeTransitionClusters(fromCluster, toCluster);
  if (!proposal || proposal.schema !== 'g-bank-ha-cluster-reconfiguration-proposal/v2') throw new Error('ha_reconfiguration_proposal_required');
  const { proposal_sha256, ...body } = proposal;
  if (sha256(canonicalJson(body)) !== hash64('ha_reconfiguration_proposal_sha256', proposal_sha256)) throw new Error('ha_reconfiguration_proposal_hash_mismatch');
  if (proposal.cluster_id !== from.cluster_id || proposal.from_cluster_sha256 !== from.cluster_sha256 || proposal.to_cluster_sha256 !== to.cluster_sha256) throw new Error('ha_reconfiguration_proposal_cluster_mismatch');
  if (proposal.from_cluster_epoch !== from.cluster_epoch || proposal.to_cluster_epoch !== to.cluster_epoch) throw new Error('ha_reconfiguration_proposal_epoch_mismatch');
  if (proposal.grants_external_rights !== false || proposal.permits_value_movement_by_itself !== false) throw new Error('ha_reconfiguration_proposal_boundary_invalid');
  return { from, to };
}

function transitionSlot(proposal, domain) {
  const d = String(domain || '').toUpperCase();
  if (!['FROM', 'TO'].includes(d)) throw new Error('ha_reconfiguration_domain_invalid');
  return `RECONFIG:${positiveInt('ha_reconfiguration_from_epoch', proposal.from_cluster_epoch)}:${positiveInt('ha_reconfiguration_to_epoch', proposal.to_cluster_epoch)}:${d}`;
}

function readRows(filePath, prefix) {
  if (!fs.existsSync(filePath)) return [];
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${prefix}_file_invalid`);
  const text = fs.readFileSync(filePath, 'utf8').trim();
  if (!text) return [];
  return text.split('\n').map((line, i) => {
    try { return JSON.parse(line); }
    catch { throw new Error(`${prefix}_corrupt_line_${i + 1}`); }
  });
}

function withLock(lockPath, busyError, fn) {
  fs.mkdirSync(path.dirname(lockPath), { recursive: true, mode: 0o700 });
  let fd;
  try { fd = fs.openSync(lockPath, 'wx', 0o600); }
  catch (err) { if (err.code === 'EEXIST') throw new Error(busyError); throw err; }
  try { return fn(); }
  finally {
    try { fs.closeSync(fd); } catch {}
    try { fs.unlinkSync(lockPath); } catch {}
  }
}

function appendDurable(filePath, record) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const fd = fs.openSync(filePath, 'a', 0o600);
  try { fs.writeSync(fd, JSON.stringify(record) + '\n'); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
}

class HAReconfigurationVoteStore {
  constructor(filePath, { node_id } = {}) {
    if (!filePath) throw new Error('ha_reconfiguration_vote_store_path_required');
    this.filePath = path.resolve(filePath);
    this.lockPath = `${this.filePath}.lock`;
    this.nodeId = nodeId(node_id);
  }

  verify() {
    const rows = readRows(this.filePath, 'ha_reconfiguration_vote_store');
    let prior = null;
    const slots = new Set();
    let maxToEpoch = 0;
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      if (row.schema !== 'g-bank-ha-reconfiguration-vote-reservation/v2' || row.sequence !== i + 1) throw new Error('ha_reconfiguration_vote_record_invalid');
      if (row.node_id !== this.nodeId) throw new Error('ha_reconfiguration_vote_node_mismatch');
      if (row.previous_record_sha256 !== prior) throw new Error('ha_reconfiguration_vote_chain_broken');
      const supplied = hash64('ha_reconfiguration_vote_record_sha256', row.record_sha256);
      const copy = { ...row }; delete copy.record_sha256;
      if (sha256(canonicalJson(copy)) !== supplied) throw new Error('ha_reconfiguration_vote_record_hash_mismatch');
      const slot = `RECONFIG:${positiveInt('ha_reconfiguration_row_from_epoch', row.from_cluster_epoch)}:${positiveInt('ha_reconfiguration_row_to_epoch', row.to_cluster_epoch)}:${String(row.quorum_domain || '').toUpperCase()}`;
      if (row.slot_key !== slot || slots.has(slot)) throw new Error('ha_reconfiguration_vote_slot_invalid');
      slots.add(slot);
      if (row.to_cluster_epoch < maxToEpoch) throw new Error('ha_reconfiguration_vote_epoch_rollback_record');
      maxToEpoch = Math.max(maxToEpoch, row.to_cluster_epoch);
      prior = supplied;
    }
    return Object.freeze({ verified: true, count: rows.length, latest_record_sha256: prior, max_to_epoch: maxToEpoch, rows: Object.freeze(rows.map(row => Object.freeze({ ...row }))) });
  }

  reserve({ proposal, quorum_domain, signing_cluster_sha256, signer_key_binding_sha256, signed_at }) {
    const domain = String(quorum_domain || '').toUpperCase();
    const slot = transitionSlot(proposal, domain);
    const proposalHash = hash64('ha_reconfiguration_vote_proposal_sha256', proposal.proposal_sha256);
    const clusterHash = hash64('ha_reconfiguration_vote_cluster_sha256', signing_cluster_sha256);
    const keyHash = hash64('ha_reconfiguration_vote_key_sha256', signer_key_binding_sha256);
    const signedAtMs = Date.parse(signed_at);
    if (!Number.isFinite(signedAtMs)) throw new Error('ha_reconfiguration_vote_signed_at_invalid');
    const signedAt = new Date(signedAtMs).toISOString();
    return withLock(this.lockPath, 'ha_reconfiguration_vote_store_busy', () => {
      const proof = this.verify();
      const existing = proof.rows.find(row => row.slot_key === slot);
      if (existing) {
        if (existing.proposal_sha256 !== proposalHash || existing.signing_cluster_sha256 !== clusterHash) throw new Error('ha_reconfiguration_vote_equivocation_detected');
        if (existing.signer_key_binding_sha256 !== keyHash || existing.signed_at !== signedAt) throw new Error('ha_reconfiguration_vote_replay_envelope_mismatch');
        return existing;
      }
      if (proposal.to_cluster_epoch < proof.max_to_epoch) throw new Error('ha_reconfiguration_vote_epoch_rollback');
      const record = {
        schema: 'g-bank-ha-reconfiguration-vote-reservation/v2',
        sequence: proof.count + 1,
        node_id: this.nodeId,
        quorum_domain: domain,
        slot_key: slot,
        from_cluster_epoch: proposal.from_cluster_epoch,
        to_cluster_epoch: proposal.to_cluster_epoch,
        signing_cluster_sha256: clusterHash,
        proposal_sha256: proposalHash,
        signer_key_binding_sha256: keyHash,
        signed_at: signedAt,
        previous_record_sha256: proof.latest_record_sha256,
        grants_external_rights: false,
        permits_value_movement_by_itself: false,
      };
      record.record_sha256 = sha256(canonicalJson(record));
      appendDurable(this.filePath, record);
      return Object.freeze({ ...record });
    });
  }
}

function reconfigurationVoteEnvelope({ proposal, domain, signingCluster, node, reservation }) {
  const d = String(domain || '').toUpperCase();
  const expectedCluster = d === 'FROM' ? proposal.from_cluster_sha256 : d === 'TO' ? proposal.to_cluster_sha256 : null;
  if (!expectedCluster) throw new Error('ha_reconfiguration_domain_invalid');
  if (signingCluster.cluster_sha256 !== expectedCluster) throw new Error('ha_reconfiguration_signing_cluster_mismatch');
  return Object.freeze({
    schema: 'g-bank-ha-reconfiguration-vote-envelope/v2',
    quorum_domain: d,
    node_id: node.node_id,
    signing_cluster_sha256: signingCluster.cluster_sha256,
    signing_cluster_epoch: signingCluster.cluster_epoch,
    reconfiguration_proposal_sha256: proposal.proposal_sha256,
    signer_key_binding_sha256: node.public_key_binding_sha256,
    vote_reservation_sha256: reservation.record_sha256,
    signed_at: reservation.signed_at,
  });
}

function signReconfigurationVote({ proposal, from_cluster, to_cluster, quorum_domain, node_id, private_key, vote_store, signed_at = new Date().toISOString() }) {
  const { from, to } = verifyReconfigurationProposal(proposal, from_cluster, to_cluster);
  const domain = String(quorum_domain || '').toUpperCase();
  const signingCluster = domain === 'FROM' ? from : domain === 'TO' ? to : null;
  if (!signingCluster) throw new Error('ha_reconfiguration_domain_invalid');
  const id = nodeId(node_id);
  const node = signingCluster.nodes.find(n => n.node_id === id && n.role === 'VOTER' && n.status === 'ACTIVE');
  if (!node) throw new Error('ha_reconfiguration_signer_not_active_voter');
  if (!vote_store || vote_store.nodeId !== id || typeof vote_store.reserve !== 'function') throw new Error('ha_reconfiguration_vote_store_required');
  const keyBinding = publicBindingFromPrivate(private_key);
  if (keyBinding !== node.public_key_binding_sha256) throw new Error('ha_reconfiguration_private_key_binding_mismatch');
  const reservation = vote_store.reserve({ proposal, quorum_domain: domain, signing_cluster_sha256: signingCluster.cluster_sha256, signer_key_binding_sha256: keyBinding, signed_at });
  const envelope = reconfigurationVoteEnvelope({ proposal, domain, signingCluster, node, reservation });
  const payload = canonicalJson(envelope);
  return Object.freeze({ ...envelope, signed_payload_sha256: sha256(payload), signature_base64: crypto.sign(null, Buffer.from(payload, 'utf8'), private_key).toString('base64') });
}

function verifyDomainVotes({ proposal, cluster, domain, signatures, voteStores, now = Date.now(), max_signature_age_ms = 300000 }) {
  if (!Array.isArray(signatures)) throw new Error('ha_reconfiguration_signatures_required');
  const accepted = [];
  const seen = new Set();
  for (const sig of signatures) {
    const id = nodeId(sig?.node_id);
    if (seen.has(id)) throw new Error('ha_reconfiguration_duplicate_signature');
    seen.add(id);
    const node = cluster.nodes.find(n => n.node_id === id && n.role === 'VOTER' && n.status === 'ACTIVE');
    if (!node) continue;
    const store = voteStores instanceof Map ? voteStores.get(id) : voteStores?.[id];
    if (!store || typeof store.verify !== 'function') throw new Error(`ha_reconfiguration_vote_store_missing:${id}`);
    const reservationHash = hash64('ha_reconfiguration_reservation_sha256', sig.vote_reservation_sha256);
    const reservation = store.verify().rows.find(row => row.record_sha256 === reservationHash);
    if (!reservation) throw new Error(`ha_reconfiguration_reservation_missing:${id}`);
    const envelope = reconfigurationVoteEnvelope({ proposal, domain, signingCluster: cluster, node, reservation });
    for (const [key, value] of Object.entries(envelope)) if (sig?.[key] !== value) throw new Error(`ha_reconfiguration_signature_envelope_mismatch:${key}`);
    const payload = canonicalJson(envelope);
    if (hash64('ha_reconfiguration_signed_payload_sha256', sig.signed_payload_sha256) !== sha256(payload)) throw new Error('ha_reconfiguration_signature_payload_hash_mismatch');
    const signedAt = Date.parse(envelope.signed_at);
    if (!Number.isFinite(signedAt) || signedAt > now + 30000 || now - signedAt > max_signature_age_ms) throw new Error('ha_reconfiguration_signature_stale_or_future');
    let ok = false;
    try { ok = crypto.verify(null, Buffer.from(payload, 'utf8'), node.public_key_pem, Buffer.from(String(sig.signature_base64 || ''), 'base64')); } catch { ok = false; }
    if (!ok) throw new Error('ha_reconfiguration_signature_invalid');
    accepted.push(Object.freeze({ ...sig }));
  }
  accepted.sort((a, b) => a.node_id.localeCompare(b.node_id));
  if (accepted.length < cluster.quorum) throw new Error(`ha_reconfiguration_${String(domain).toLowerCase()}_quorum_not_met`);
  return accepted;
}

function createJointReconfigurationCertificate({ proposal, from_cluster, to_cluster, from_signatures, to_signatures, voteStores, now = Date.now() }) {
  const { from, to } = verifyReconfigurationProposal(proposal, from_cluster, to_cluster);
  const fromAccepted = verifyDomainVotes({ proposal, cluster: from, domain: 'FROM', signatures: from_signatures, voteStores, now });
  const toAccepted = verifyDomainVotes({ proposal, cluster: to, domain: 'TO', signatures: to_signatures, voteStores, now });
  const body = {
    schema: 'g-bank-ha-joint-reconfiguration-certificate/v2',
    proposal_sha256: proposal.proposal_sha256,
    from_cluster_sha256: from.cluster_sha256,
    to_cluster_sha256: to.cluster_sha256,
    from_quorum_required: from.quorum,
    to_quorum_required: to.quorum,
    from_signer_node_ids: fromAccepted.map(sig => sig.node_id),
    to_signer_node_ids: toAccepted.map(sig => sig.node_id),
    from_signatures: fromAccepted,
    to_signatures: toAccepted,
    verified_at: new Date(now).toISOString(),
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
  };
  return Object.freeze({ ...body, certificate_sha256: sha256(canonicalJson(body)) });
}

function verifyJointReconfigurationCertificate({ proposal, from_cluster, to_cluster, certificate, voteStores }) {
  if (!certificate || certificate.schema !== 'g-bank-ha-joint-reconfiguration-certificate/v2') throw new Error('ha_reconfiguration_certificate_required');
  const supplied = hash64('ha_reconfiguration_certificate_sha256', certificate.certificate_sha256);
  const { certificate_sha256, ...body } = certificate;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('ha_reconfiguration_certificate_hash_mismatch');
  if (certificate.grants_external_rights !== false || certificate.permits_value_movement_by_itself !== false) throw new Error('ha_reconfiguration_certificate_boundary_invalid');
  const verifiedAt = Date.parse(certificate.verified_at);
  if (!Number.isFinite(verifiedAt)) throw new Error('ha_reconfiguration_certificate_time_invalid');
  const reconstructed = createJointReconfigurationCertificate({ proposal, from_cluster, to_cluster, from_signatures: certificate.from_signatures, to_signatures: certificate.to_signatures, voteStores, now: verifiedAt });
  if (reconstructed.certificate_sha256 !== supplied) throw new Error('ha_reconfiguration_certificate_reverification_mismatch');
  return true;
}

class HAClusterAuthorityStore {
  constructor(filePath, genesisCluster, { voteStores } = {}) {
    if (!filePath) throw new Error('ha_cluster_authority_path_required');
    this.filePath = path.resolve(filePath);
    this.lockPath = `${this.filePath}.lock`;
    this.genesisCluster = normalizeCluster(genesisCluster);
    this.voteStores = voteStores || {};
  }

  verify() {
    const rows = readRows(this.filePath, 'ha_cluster_authority_store');
    let current = this.genesisCluster;
    let prior = null;
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      if (row.schema !== 'g-bank-ha-cluster-transition-record/v2' || row.sequence !== i + 1) throw new Error('ha_cluster_transition_record_invalid');
      if (row.previous_transition_sha256 !== prior) throw new Error('ha_cluster_transition_chain_broken');
      const supplied = hash64('ha_cluster_transition_record_sha256', row.record_sha256);
      const copy = { ...row }; delete copy.record_sha256;
      if (sha256(canonicalJson(copy)) !== supplied) throw new Error('ha_cluster_transition_record_hash_mismatch');
      if (row.from_cluster.cluster_sha256 !== current.cluster_sha256 || row.from_cluster.cluster_epoch !== current.cluster_epoch) throw new Error('ha_cluster_transition_from_current_mismatch');
      verifyReconfigurationProposal(row.proposal, row.from_cluster, row.to_cluster);
      if (row.proposal.previous_transition_sha256 !== prior) throw new Error('ha_cluster_transition_proposal_previous_mismatch');
      verifyJointReconfigurationCertificate({ proposal: row.proposal, from_cluster: row.from_cluster, to_cluster: row.to_cluster, certificate: row.joint_certificate, voteStores: this.voteStores });
      current = normalizeCluster(row.to_cluster);
      prior = supplied;
    }
    const rootBody = { schema: 'g-bank-ha-cluster-authority-root/v2', genesis_cluster_sha256: this.genesisCluster.cluster_sha256, transition_head_sha256: prior, current_cluster_sha256: current.cluster_sha256, current_cluster_epoch: current.cluster_epoch };
    return Object.freeze({ verified: true, transition_count: rows.length, transition_head_sha256: prior, current_cluster: current, cluster_authority_root_sha256: sha256(canonicalJson(rootBody)), rows: Object.freeze(rows.map(row => Object.freeze({ ...row }))) });
  }

  commit({ proposal, from_cluster, to_cluster, joint_certificate, fenceStore, commitStore, now = Date.now() }) {
    return withLock(this.lockPath, 'ha_cluster_authority_busy', () => {
      const proof = this.verify();
      const { from, to } = verifyReconfigurationProposal(proposal, from_cluster, to_cluster);
      if (from.cluster_sha256 !== proof.current_cluster.cluster_sha256 || from.cluster_epoch !== proof.current_cluster.cluster_epoch) throw new Error('ha_reconfiguration_from_not_current');
      if (proposal.previous_transition_sha256 !== proof.transition_head_sha256) throw new Error('ha_reconfiguration_previous_transition_mismatch');
      if (!fenceStore || !commitStore) throw new Error('ha_reconfiguration_state_stores_required');
      const fence = fenceStore.verify().latest;
      const commit = commitStore.verify().latest;
      if (!fence || !commit) throw new Error('ha_reconfiguration_live_state_required');
      if (proposal.active_fence_record_sha256 !== fence.record_sha256 || proposal.active_fence_term !== fence.term || proposal.active_leader_node_id !== fence.leader_node_id) throw new Error('ha_reconfiguration_active_fence_changed');
      if (proposal.latest_commit_sha256 !== commit.record_sha256 || proposal.latest_commit_index !== commit.commit_index || proposal.replicated_state_root_sha256 !== commit.state_root_sha256) throw new Error('ha_reconfiguration_latest_commit_changed');
      if (Date.parse(fence.valid_until) <= now || Date.parse(fence.valid_from) > now) throw new Error('ha_reconfiguration_fence_not_current');
      verifyJointReconfigurationCertificate({ proposal, from_cluster: from, to_cluster: to, certificate: joint_certificate, voteStores: this.voteStores });
      const record = {
        schema: 'g-bank-ha-cluster-transition-record/v2',
        sequence: proof.transition_count + 1,
        from_cluster: from,
        to_cluster: to,
        proposal,
        joint_certificate,
        previous_transition_sha256: proof.transition_head_sha256,
        committed_at: new Date(now).toISOString(),
        grants_external_rights: false,
        permits_value_movement_by_itself: false,
      };
      record.record_sha256 = sha256(canonicalJson(record));
      appendDurable(this.filePath, record);
      return Object.freeze({ record: Object.freeze(record), current_cluster: to });
    });
  }
}

module.exports = {
  HAReconfigurationVoteStore,
  HAClusterAuthorityStore,
  createClusterReconfigurationProposal,
  verifyReconfigurationProposal,
  signReconfigurationVote,
  createJointReconfigurationCertificate,
  verifyJointReconfigurationCertificate,
  transitionSlot,
};
