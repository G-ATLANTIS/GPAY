'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { normalizeCluster, createFenceProposal, createCommitProposal, signProposal } = require('../g-bank-sovereign-v2/ha-quorum');
const { HAVoteStore } = require('../g-bank-sovereign-v2/ha-vote-store');
const { HAFenceStore, HACommitStore } = require('../g-bank-sovereign-v2/ha-replication-store');
const {
  HAReconfigurationVoteStore,
  HAClusterAuthorityStore,
  createClusterReconfigurationProposal,
  signReconfigurationVote,
  createJointReconfigurationCertificate,
  verifyJointReconfigurationCertificate,
} = require('../g-bank-sovereign-v2/ha-cluster-authority');

const NOW = Date.parse('2026-09-10T10:45:00.000Z');
const H = c => c.repeat(64);

function keyNode(id) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { node_id: id, role: 'VOTER', status: 'ACTIVE', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), privateKey };
}
function pub(node) { const { privateKey, ...rest } = node; return rest; }

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-ha-reconfig-v2-'));
const A = keyNode('NODE:A');
const B = keyNode('NODE:B');
const C = keyNode('NODE:C');
const D = keyNode('NODE:D');
const byId = Object.fromEntries([A, B, C, D].map(node => [node.node_id, node]));
const cluster1 = { cluster_id: 'G-BANK-HA-PRIMARY', cluster_epoch: 1, nodes: [pub(A), pub(B), pub(C)] };
const cluster2 = { cluster_id: 'G-BANK-HA-PRIMARY', cluster_epoch: 2, nodes: [pub(B), pub(C), pub(D)] };
const normalized1 = normalizeCluster(cluster1);
const normalized2 = normalizeCluster(cluster2);
assert.equal(normalized1.quorum, 2);
assert.equal(normalized2.quorum, 2);

const opVoteStores = Object.fromEntries([A, B, C].map(node => [node.node_id, new HAVoteStore(path.join(root, `op-${node.node_id}.jsonl`), { node_id: node.node_id })]));
const fenceStore = new HAFenceStore(path.join(root, 'fences.jsonl'), cluster1);
const commitStore = new HACommitStore(path.join(root, 'commits.jsonl'), cluster1, fenceStore);
const fenceProposal = createFenceProposal({
  cluster: cluster1, term: 1, leader_node_id: 'NODE:A', previous_fence_sha256: null,
  valid_from: new Date(NOW - 1000).toISOString(), valid_until: new Date(NOW + 240000).toISOString(),
});
const fenceSignatures = [A, B].map(node => signProposal({ proposal: fenceProposal, node_id: node.node_id, private_key: node.privateKey, signed_at: new Date(NOW).toISOString(), vote_store: opVoteStores[node.node_id] }));
const fence = fenceStore.commit({ proposal: fenceProposal, signatures: fenceSignatures, now: NOW }).record;
const commitProposal = createCommitProposal({
  cluster: cluster1, term: 1, leader_node_id: 'NODE:A', commit_index: 1, state_root_sha256: H('a'),
  fence_record_sha256: fence.record_sha256, previous_commit_sha256: null,
});
const commitSignatures = [A, B].map(node => signProposal({ proposal: commitProposal, node_id: node.node_id, private_key: node.privateKey, signed_at: new Date(NOW + 1000).toISOString(), vote_store: opVoteStores[node.node_id] }));
const commit = commitStore.commit({ proposal: commitProposal, signatures: commitSignatures, now: NOW + 1000 }).record;

const reconfigStores = Object.fromEntries([A, B, C, D].map(node => [node.node_id, new HAReconfigurationVoteStore(path.join(root, `reconfig-${node.node_id}.jsonl`), { node_id: node.node_id })]));
const authorityStore = new HAClusterAuthorityStore(path.join(root, 'cluster-authority.jsonl'), cluster1, { voteStores: reconfigStores });
const genesis = authorityStore.verify();
assert.equal(genesis.transition_count, 0);
assert.equal(genesis.current_cluster.cluster_sha256, normalized1.cluster_sha256);
assert.match(genesis.cluster_authority_root_sha256, /^[0-9a-f]{64}$/);

const proposal = createClusterReconfigurationProposal({
  from_cluster: cluster1,
  to_cluster: cluster2,
  active_fence: fence,
  latest_commit: commit,
  previous_transition_sha256: null,
  proposed_at: new Date(NOW + 2000).toISOString(),
});
assert.equal(proposal.from_cluster_sha256, normalized1.cluster_sha256);
assert.equal(proposal.to_cluster_sha256, normalized2.cluster_sha256);
assert.equal(proposal.replicated_state_root_sha256, H('a'));

function reconfigSign(node, domain) {
  return signReconfigurationVote({
    proposal, from_cluster: cluster1, to_cluster: cluster2, quorum_domain: domain,
    node_id: node.node_id, private_key: node.privateKey, vote_store: reconfigStores[node.node_id],
    signed_at: new Date(NOW + 2000).toISOString(),
  });
}
const fromSignatures = [reconfigSign(A, 'FROM'), reconfigSign(B, 'FROM')];
const toSignatures = [reconfigSign(B, 'TO'), reconfigSign(D, 'TO')];
assert.throws(() => createJointReconfigurationCertificate({ proposal, from_cluster: cluster1, to_cluster: cluster2, from_signatures: [fromSignatures[0]], to_signatures, voteStores: reconfigStores, now: NOW + 2000 }), /ha_reconfiguration_from_quorum_not_met/);
assert.throws(() => createJointReconfigurationCertificate({ proposal, from_cluster: cluster1, to_cluster: cluster2, from_signatures, to_signatures: [toSignatures[0]], voteStores: reconfigStores, now: NOW + 2000 }), /ha_reconfiguration_to_quorum_not_met/);

const certificate = createJointReconfigurationCertificate({ proposal, from_cluster: cluster1, to_cluster: cluster2, from_signatures, to_signatures, voteStores: reconfigStores, now: NOW + 2000 });
assert.equal(certificate.from_signer_node_ids.length, 2);
assert.equal(certificate.to_signer_node_ids.length, 2);
assert.equal(verifyJointReconfigurationCertificate({ proposal, from_cluster: cluster1, to_cluster: cluster2, certificate, voteStores: reconfigStores }), true);

const transition = authorityStore.commit({ proposal, from_cluster: cluster1, to_cluster: cluster2, joint_certificate: certificate, fenceStore, commitStore, now: NOW + 2000 });
assert.equal(transition.current_cluster.cluster_sha256, normalized2.cluster_sha256);
const authority = authorityStore.verify();
assert.equal(authority.transition_count, 1);
assert.equal(authority.current_cluster.cluster_epoch, 2);
assert.equal(authority.current_cluster.cluster_sha256, normalized2.cluster_sha256);
assert.match(authority.transition_head_sha256, /^[0-9a-f]{64}$/);
assert.match(authority.cluster_authority_root_sha256, /^[0-9a-f]{64}$/);

const competingCluster2 = { cluster_id: 'G-BANK-HA-PRIMARY', cluster_epoch: 2, nodes: [pub(A), pub(C), pub(D)] };
const competing = createClusterReconfigurationProposal({
  from_cluster: cluster1, to_cluster: competingCluster2, active_fence: fence, latest_commit: commit,
  previous_transition_sha256: null, proposed_at: new Date(NOW + 2000).toISOString(),
});
assert.throws(() => signReconfigurationVote({
  proposal: competing, from_cluster: cluster1, to_cluster: competingCluster2, quorum_domain: 'FROM',
  node_id: 'NODE:A', private_key: A.privateKey, vote_store: reconfigStores['NODE:A'], signed_at: new Date(NOW + 2000).toISOString(),
}), /ha_reconfiguration_vote_equivocation_detected/);

const wrongKey = keyNode('NODE:WRONG');
assert.throws(() => signReconfigurationVote({
  proposal, from_cluster: cluster1, to_cluster: cluster2, quorum_domain: 'TO', node_id: 'NODE:B',
  private_key: wrongKey.privateKey, vote_store: reconfigStores['NODE:B'], signed_at: new Date(NOW + 2000).toISOString(),
}), /ha_reconfiguration_private_key_binding_mismatch/);

const tamperedCertificate = { ...certificate, to_signatures: certificate.to_signatures.map((sig, i) => i ? sig : { ...sig, signature_base64: Buffer.from('forged').toString('base64') }) };
assert.throws(() => verifyJointReconfigurationCertificate({ proposal, from_cluster: cluster1, to_cluster: cluster2, certificate: tamperedCertificate, voteStores: reconfigStores }), /ha_reconfiguration_certificate_hash_mismatch/);

assert.throws(() => createClusterReconfigurationProposal({
  from_cluster: cluster1,
  to_cluster: { ...cluster2, cluster_epoch: 3 },
  active_fence: fence,
  latest_commit: commit,
}), /ha_reconfiguration_next_epoch_required/);

assert.throws(() => authorityStore.commit({ proposal, from_cluster: cluster1, to_cluster: cluster2, joint_certificate: certificate, fenceStore, commitStore, now: NOW + 3000 }), /ha_reconfiguration_from_not_current/);

for (const store of Object.values(reconfigStores)) assert.equal(store.verify().verified, true);

console.log('G-BANK sovereign v2 joint-quorum HA reconfiguration tests: PASS');
