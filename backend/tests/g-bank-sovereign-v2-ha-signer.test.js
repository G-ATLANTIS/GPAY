'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { normalizeCluster, createFenceProposal, verifyQuorumCertificate } = require('../g-bank-sovereign-v2/ha-quorum');
const { HAVoteStore } = require('../g-bank-sovereign-v2/ha-vote-store');
const { HADurableSigner } = require('../g-bank-sovereign-v2/ha-durable-signer');

const NOW = Date.parse('2026-09-10T10:30:00.000Z');

function keyNode(id) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    node_id: id,
    role: 'VOTER',
    status: 'ACTIVE',
    public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey,
  };
}

function publicNodes(nodes) {
  return nodes.map(({ privateKey, ...node }) => ({ ...node }));
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-ha-signer-v2-'));
const nodes = [keyNode('NODE:A'), keyNode('NODE:B'), keyNode('NODE:C'), keyNode('NODE:D')];
const cluster1 = { cluster_id: 'G-BANK-HA-PRIMARY', cluster_epoch: 1, nodes: publicNodes(nodes) };
const normalized1 = normalizeCluster(cluster1);
const stores = Object.fromEntries(nodes.map(node => [node.node_id, new HAVoteStore(path.join(root, `${node.node_id.replace(':', '-')}.votes.jsonl`), { node_id: node.node_id })]));

const signers1 = Object.fromEntries(nodes.map(node => [node.node_id, new HADurableSigner({
  cluster: cluster1,
  node_id: node.node_id,
  private_key: node.privateKey,
  vote_store: stores[node.node_id],
  clock: () => NOW,
})]));

const fence1 = createFenceProposal({
  cluster: cluster1,
  term: 1,
  leader_node_id: 'NODE:A',
  previous_fence_sha256: null,
  valid_from: new Date(NOW - 1000).toISOString(),
  valid_until: new Date(NOW + 180000).toISOString(),
});
const sigA = signers1['NODE:A'].sign(fence1);
const sigB = signers1['NODE:B'].sign(fence1);
const sigC = signers1['NODE:C'].sign(fence1);
assert.equal(verifyQuorumCertificate({ cluster: cluster1, proposal: fence1, signatures: [sigA, sigB, sigC], now: NOW }).signer_node_ids.length, 3);
assert.equal(signers1['NODE:A'].verifyJournal().count, 1);

const replayA = signers1['NODE:A'].sign(fence1);
assert.equal(replayA.signature_base64, sigA.signature_base64);
assert.equal(signers1['NODE:A'].verifyJournal().count, 1, 'exact replay must not append a second vote reservation');

const laterClockSignerA = new HADurableSigner({
  cluster: cluster1,
  node_id: 'NODE:A',
  private_key: nodes[0].privateKey,
  vote_store: stores['NODE:A'],
  clock: () => NOW + 60000,
});
const laterReplayA = laterClockSignerA.sign(fence1);
assert.equal(laterReplayA.signed_at, sigA.signed_at, 'implicit replay must reuse the original reserved timestamp');
assert.equal(laterReplayA.signature_base64, sigA.signature_base64, 'implicit replay must reproduce the exact Ed25519 signature');
assert.equal(stores['NODE:A'].verify().count, 1);
assert.throws(() => laterClockSignerA.sign(fence1, { signed_at: new Date(NOW + 60000).toISOString() }), /ha_vote_replay_envelope_mismatch/);

const conflictingFence1 = createFenceProposal({
  cluster: cluster1,
  term: 1,
  leader_node_id: 'NODE:B',
  previous_fence_sha256: null,
  valid_from: new Date(NOW - 1000).toISOString(),
  valid_until: new Date(NOW + 180000).toISOString(),
});
assert.throws(() => signers1['NODE:A'].sign(conflictingFence1), /ha_vote_equivocation_detected/);

assert.throws(() => new HADurableSigner({
  cluster: cluster1,
  node_id: 'NODE:A',
  private_key: nodes[1].privateKey,
  vote_store: stores['NODE:A'],
}), /ha_signer_private_key_binding_mismatch/);

assert.throws(() => new HADurableSigner({
  cluster: cluster1,
  node_id: 'NODE:A',
  private_key: nodes[0].privateKey,
  vote_store: null,
}), /ha_signer_vote_store_required/);

const cluster2 = { cluster_id: 'G-BANK-HA-PRIMARY', cluster_epoch: 2, nodes: publicNodes(nodes) };
const normalized2 = normalizeCluster(cluster2);
assert.notEqual(normalized2.cluster_sha256, normalized1.cluster_sha256);
const signerA2 = new HADurableSigner({ cluster: cluster2, node_id: 'NODE:A', private_key: nodes[0].privateKey, vote_store: stores['NODE:A'], clock: () => NOW + 1000 });
const fence2 = createFenceProposal({
  cluster: cluster2,
  term: 1,
  leader_node_id: 'NODE:A',
  previous_fence_sha256: null,
  valid_from: new Date(NOW).toISOString(),
  valid_until: new Date(NOW + 180000).toISOString(),
});
assert.doesNotThrow(() => signerA2.sign(fence2));
assert.equal(stores['NODE:A'].verify().max_cluster_epoch, 2);

const oldEpochFence = createFenceProposal({
  cluster: cluster1,
  term: 2,
  leader_node_id: 'NODE:A',
  previous_fence_sha256: 'a'.repeat(64),
  valid_from: new Date(NOW).toISOString(),
  valid_until: new Date(NOW + 180000).toISOString(),
});
assert.throws(() => signers1['NODE:A'].sign(oldEpochFence, { signed_at: new Date(NOW + 2000).toISOString() }), /ha_vote_cluster_epoch_rollback/);

const extra = keyNode('NODE:E');
const changedEpoch2 = { cluster_id: 'G-BANK-HA-PRIMARY', cluster_epoch: 2, nodes: [...publicNodes(nodes), ...publicNodes([extra])] };
const changedSignerA2 = new HADurableSigner({ cluster: changedEpoch2, node_id: 'NODE:A', private_key: nodes[0].privateKey, vote_store: stores['NODE:A'], clock: () => NOW + 3000 });
const changedFence = createFenceProposal({
  cluster: changedEpoch2,
  term: 2,
  leader_node_id: 'NODE:A',
  previous_fence_sha256: 'b'.repeat(64),
  valid_from: new Date(NOW).toISOString(),
  valid_until: new Date(NOW + 180000).toISOString(),
});
assert.throws(() => changedSignerA2.sign(changedFence), /ha_vote_cluster_changed_without_epoch_bump/);

const inactiveACluster = {
  cluster_id: 'G-BANK-HA-PRIMARY',
  cluster_epoch: 3,
  nodes: publicNodes(nodes).map(node => node.node_id === 'NODE:A' ? { ...node, role: 'LEARNER' } : node),
};
assert.throws(() => new HADurableSigner({
  cluster: inactiveACluster,
  node_id: 'NODE:A',
  private_key: nodes[0].privateKey,
  vote_store: stores['NODE:A'],
}), /ha_signer_node_not_active_voter/);

console.log('G-BANK sovereign v2 durable HA signer tests: PASS');
