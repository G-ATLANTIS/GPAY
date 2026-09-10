'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { normalizeCluster } = require('./ha-quorum');

function storeFor(voteStores, nodeId) {
  if (voteStores instanceof Map) return voteStores.get(nodeId) || null;
  return voteStores?.[nodeId] || null;
}

function assessHAReadiness({ cluster, clusterAuthorityStore = null, fenceStore, commitStore, voteStores = null, checkpoint, now = Date.now(), max_commit_age_ms = 120000 } = {}) {
  const c = normalizeCluster(cluster);
  if (!fenceStore || !commitStore) throw new Error('ha_stores_required');
  if (!checkpoint || checkpoint.schema !== 'g-bank-sovereign-state-checkpoint/v2') throw new Error('ha_checkpoint_required');
  const fenceProof = fenceStore.verify();
  const commitProof = commitStore.verify();
  const fence = fenceProof.latest;
  const commit = commitProof.latest;
  const reasons = [];

  let clusterAuthority = null;
  if (!clusterAuthorityStore || typeof clusterAuthorityStore.verify !== 'function') {
    reasons.push('CLUSTER_AUTHORITY_STORE_MISSING');
  } else {
    clusterAuthority = clusterAuthorityStore.verify();
    if (clusterAuthority.current_cluster?.cluster_sha256 !== c.cluster_sha256 || clusterAuthority.current_cluster?.cluster_epoch !== c.cluster_epoch) {
      reasons.push('CLUSTER_NOT_CANONICAL_AUTHORITY_HEAD');
    }
  }

  if (!fence) reasons.push('NO_FENCE');
  if (!commit) reasons.push('NO_COMMIT');
  if (fence && Date.parse(fence.valid_until) <= now) reasons.push('FENCE_EXPIRED');
  if (fence && Date.parse(fence.valid_from) > now) reasons.push('FENCE_NOT_STARTED');
  if (commit && now - Date.parse(commit.committed_at) > max_commit_age_ms) reasons.push('COMMIT_STALE');
  if (commit && commit.state_root_sha256 !== checkpoint.state_root_sha256) reasons.push('CHECKPOINT_NOT_REPLICATED');
  if (fence && commit && (commit.term !== fence.term || commit.leader_node_id !== fence.leader_node_id || commit.fence_record_sha256 !== fence.record_sha256)) reasons.push('COMMIT_NOT_ON_ACTIVE_FENCE');
  if (fence && fence.cluster_sha256 !== c.cluster_sha256) reasons.push('FENCE_CLUSTER_MISMATCH');
  if (commit && commit.cluster_sha256 !== c.cluster_sha256) reasons.push('COMMIT_CLUSTER_MISMATCH');

  const activeVoters = c.nodes.filter(node => node.role === 'VOTER' && node.status === 'ACTIVE');
  const journalHeads = {};
  const journalProofs = new Map();
  let verifiedVoteStoreCount = 0;
  for (const node of activeVoters) {
    const store = storeFor(voteStores, node.node_id);
    if (!store || typeof store.verify !== 'function') {
      reasons.push(`VOTE_STORE_MISSING:${node.node_id}`);
      journalHeads[node.node_id] = null;
      continue;
    }
    if (store.nodeId !== node.node_id) {
      reasons.push(`VOTE_STORE_NODE_MISMATCH:${node.node_id}`);
      journalHeads[node.node_id] = null;
      continue;
    }
    const proof = store.verify();
    journalProofs.set(node.node_id, proof);
    journalHeads[node.node_id] = proof.latest_record_sha256;
    verifiedVoteStoreCount += 1;
  }

  const durableVoteCount = (record, label) => {
    if (!record?.quorum_certificate?.signer_node_ids || !record?.proposal_sha256) return 0;
    let count = 0;
    for (const signerId of record.quorum_certificate.signer_node_ids) {
      const proof = journalProofs.get(signerId);
      const signature = record.quorum_certificate.signatures?.find(sig => sig.node_id === signerId);
      const durable = proof?.rows?.some(row =>
        row.proposal_sha256 === record.proposal_sha256 &&
        row.cluster_sha256 === c.cluster_sha256 &&
        row.cluster_epoch === c.cluster_epoch &&
        row.record_sha256 === signature?.vote_reservation_sha256 &&
        row.signer_key_binding_sha256 === signature?.signer_key_binding_sha256 &&
        row.signed_at === signature?.signed_at
      );
      if (!durable) reasons.push(`${label}_SIGNER_VOTE_NOT_DURABLE:${signerId}`);
      else count += 1;
    }
    return count;
  };
  const durableFenceSignerCount = durableVoteCount(fence, 'FENCE');
  const durableCommitSignerCount = durableVoteCount(commit, 'COMMIT');
  if (fence && durableFenceSignerCount < c.quorum) reasons.push('FENCE_DURABLE_QUORUM_NOT_MET');
  if (commit && durableCommitSignerCount < c.quorum) reasons.push('COMMIT_DURABLE_QUORUM_NOT_MET');

  const orderedJournalHeads = Object.freeze(Object.fromEntries(Object.entries(journalHeads).sort(([a], [b]) => a.localeCompare(b))));
  const voterJournalRoot = sha256(canonicalJson(orderedJournalHeads));

  const body = {
    schema: 'g-bank-ha-readiness-audit/v2',
    state: reasons.length ? 'BLOCK' : 'PASS',
    cluster_sha256: c.cluster_sha256,
    cluster_epoch: c.cluster_epoch,
    cluster_authority_root_sha256: clusterAuthority?.cluster_authority_root_sha256 || null,
    cluster_transition_count: clusterAuthority?.transition_count ?? null,
    cluster_transition_head_sha256: clusterAuthority?.transition_head_sha256 || null,
    active_voter_count: c.active_voter_count,
    quorum: c.quorum,
    latest_term: fenceProof.latest_term,
    leader_node_id: fence?.leader_node_id || null,
    fence_record_sha256: fence?.record_sha256 || null,
    fence_valid_until: fence?.valid_until || null,
    latest_commit_index: commitProof.latest_commit_index,
    latest_commit_sha256: commit?.record_sha256 || null,
    replicated_state_root_sha256: commit?.state_root_sha256 || null,
    checkpoint_state_root_sha256: checkpoint.state_root_sha256,
    voter_journal_store_count: verifiedVoteStoreCount,
    voter_journal_heads: orderedJournalHeads,
    voter_journal_root_sha256: voterJournalRoot,
    durable_fence_signer_count: durableFenceSignerCount,
    durable_commit_signer_count: durableCommitSignerCount,
    reasons,
    audited_at: new Date(now).toISOString(),
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
    distributed_network_verified: false,
  };
  return Object.freeze({ ...body, audit_sha256: sha256(canonicalJson(body)) });
}

module.exports = { assessHAReadiness, storeFor };
