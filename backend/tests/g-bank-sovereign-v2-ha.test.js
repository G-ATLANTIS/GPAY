'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { normalizeCluster, createFenceProposal, createCommitProposal, signProposal, verifyQuorumCertificate } = require('../g-bank-sovereign-v2/ha-quorum');
const { HAFenceStore, HACommitStore } = require('../g-bank-sovereign-v2/ha-replication-store');
const { assessHAReadiness } = require('../g-bank-sovereign-v2/ha-readiness-audit');

const NOW = Date.parse('2026-09-10T10:00:00.000Z');
const H = c => c.repeat(64);

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

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-ha-v2-'));
  const nodes = [keyNode('NODE:A'), keyNode('NODE:B'), keyNode('NODE:C')];
  const clusterInput = { cluster_id: 'G-BANK-HA-PRIMARY', cluster_epoch: 1, nodes: nodes.map(({ privateKey, ...n }) => n) };
  const cluster = normalizeCluster(clusterInput);
  const fenceStore = new HAFenceStore(path.join(root, 'fences.jsonl'), clusterInput);
  const commitStore = new HACommitStore(path.join(root, 'commits.jsonl'), clusterInput, fenceStore);
  return { root, nodes, clusterInput, cluster, fenceStore, commitStore };
}

function signatures(proposal, nodes, count = 2) {
  return nodes.slice(0, count).map(node => signProposal({ proposal, node_id: node.node_id, private_key: node.privateKey, signed_at: new Date(NOW).toISOString() }));
}

(() => {
  const f = fixture();
  assert.equal(f.cluster.quorum, 2);
  const fence = createFenceProposal({
    cluster: f.clusterInput,
    term: 1,
    leader_node_id: 'NODE:A',
    previous_fence_sha256: null,
    valid_from: new Date(NOW - 1000).toISOString(),
    valid_until: new Date(NOW + 240000).toISOString(),
  });

  assert.throws(() => verifyQuorumCertificate({ cluster: f.clusterInput, proposal: fence, signatures: signatures(fence, f.nodes, 1), now: NOW }), /ha_quorum_not_met/);
  const duplicate = signatures(fence, f.nodes, 1);
  assert.throws(() => verifyQuorumCertificate({ cluster: f.clusterInput, proposal: fence, signatures: [duplicate[0], duplicate[0]], now: NOW }), /ha_duplicate_signature/);

  const committedFence = f.fenceStore.commit({ proposal: fence, signatures: signatures(fence, f.nodes), now: NOW });
  assert.equal(committedFence.record.term, 1);
  assert.equal(committedFence.record.leader_node_id, 'NODE:A');

  const splitBrain = createFenceProposal({
    cluster: f.clusterInput,
    term: 1,
    leader_node_id: 'NODE:B',
    previous_fence_sha256: null,
    valid_from: new Date(NOW - 1000).toISOString(),
    valid_until: new Date(NOW + 240000).toISOString(),
  });
  assert.throws(() => f.fenceStore.commit({ proposal: splitBrain, signatures: signatures(splitBrain, f.nodes), now: NOW }), /ha_fence_next_term_required/);

  const commit1 = createCommitProposal({
    cluster: f.clusterInput,
    term: 1,
    leader_node_id: 'NODE:A',
    commit_index: 1,
    state_root_sha256: H('a'),
    fence_record_sha256: committedFence.record.record_sha256,
    previous_commit_sha256: null,
  });
  const committed = f.commitStore.commit({ proposal: commit1, signatures: signatures(commit1, f.nodes), now: NOW + 1000 });
  assert.equal(committed.record.commit_index, 1);

  assert.throws(() => f.commitStore.commit({ proposal: commit1, signatures: signatures(commit1, f.nodes), now: NOW + 2000 }), /ha_commit_next_index_required/);

  const gap = createCommitProposal({
    cluster: f.clusterInput,
    term: 1,
    leader_node_id: 'NODE:A',
    commit_index: 3,
    state_root_sha256: H('b'),
    fence_record_sha256: committedFence.record.record_sha256,
    previous_commit_sha256: committed.record.record_sha256,
  });
  assert.throws(() => f.commitStore.commit({ proposal: gap, signatures: signatures(gap, f.nodes), now: NOW + 2000 }), /ha_commit_next_index_required/);

  const checkpoint = { schema: 'g-bank-sovereign-state-checkpoint/v2', state_root_sha256: H('a') };
  const audit = assessHAReadiness({ cluster: f.clusterInput, fenceStore: f.fenceStore, commitStore: f.commitStore, checkpoint, now: NOW + 2000 });
  assert.equal(audit.state, 'PASS');
  assert.equal(audit.latest_commit_index, 1);
  assert.equal(audit.distributed_network_verified, false);
  assert.equal(audit.grants_external_rights, false);
  assert.match(audit.audit_sha256, /^[0-9a-f]{64}$/);

  const mismatch = assessHAReadiness({ cluster: f.clusterInput, fenceStore: f.fenceStore, commitStore: f.commitStore, checkpoint: { ...checkpoint, state_root_sha256: H('c') }, now: NOW + 2000 });
  assert.equal(mismatch.state, 'BLOCK');
  assert.ok(mismatch.reasons.includes('CHECKPOINT_NOT_REPLICATED'));

  const stale = assessHAReadiness({ cluster: f.clusterInput, fenceStore: f.fenceStore, commitStore: f.commitStore, checkpoint, now: NOW + 130000, max_commit_age_ms: 120000 });
  assert.equal(stale.state, 'BLOCK');
  assert.ok(stale.reasons.includes('COMMIT_STALE'));

  const fenceFile = path.join(f.root, 'fences.jsonl');
  const rows = fs.readFileSync(fenceFile, 'utf8').trim().split('\n').map(JSON.parse);
  rows[0].leader_node_id = 'NODE:C';
  fs.writeFileSync(fenceFile, rows.map(JSON.stringify).join('\n') + '\n');
  assert.throws(() => f.fenceStore.verify(), /ha_fence_record_hash_mismatch/);
})();

(() => {
  const f = fixture();
  const fence = createFenceProposal({
    cluster: f.clusterInput,
    term: 1,
    leader_node_id: 'NODE:A',
    previous_fence_sha256: null,
    valid_from: new Date(NOW - 300000).toISOString(),
    valid_until: new Date(NOW - 1).toISOString(),
  });
  assert.throws(() => f.fenceStore.commit({ proposal: fence, signatures: signatures(fence, f.nodes), now: NOW }), /ha_fence_not_current/);
})();

console.log('G-BANK sovereign v2 HA quorum/fencing tests: PASS');
