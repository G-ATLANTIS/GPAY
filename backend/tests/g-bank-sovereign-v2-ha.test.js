'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { normalizeCluster, createFenceProposal, createCommitProposal, signProposal, verifyQuorumCertificate } = require('../g-bank-sovereign-v2/ha-quorum');
const { HAFenceStore, HACommitStore } = require('../g-bank-sovereign-v2/ha-replication-store');
const { HAVoteStore } = require('../g-bank-sovereign-v2/ha-vote-store');
const { assessHAReadiness } = require('../g-bank-sovereign-v2/ha-readiness-audit');

const NOW = Date.parse('2026-09-10T10:00:00.000Z');
const H = c => c.repeat(64);

function keyNode(id) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { node_id: id, role: 'VOTER', status: 'ACTIVE', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString(), privateKey };
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-ha-v2-'));
  const nodes = [keyNode('NODE:A'), keyNode('NODE:B'), keyNode('NODE:C')];
  const clusterInput = { cluster_id: 'G-BANK-HA-PRIMARY', cluster_epoch: 1, nodes: nodes.map(({ privateKey, ...node }) => node) };
  const cluster = normalizeCluster(clusterInput);
  const fenceStore = new HAFenceStore(path.join(root, 'fences.jsonl'), clusterInput);
  const commitStore = new HACommitStore(path.join(root, 'commits.jsonl'), clusterInput, fenceStore);
  const voteStores = Object.fromEntries(nodes.map(node => [node.node_id, new HAVoteStore(path.join(root, `votes-${node.node_id.replace(':', '-')}.jsonl`), { node_id: node.node_id })]));
  return { root, nodes, clusterInput, cluster, fenceStore, commitStore, voteStores };
}

function signatures(proposal, f, count = 2, signedAt = NOW) {
  return f.nodes.slice(0, count).map(node => signProposal({
    proposal,
    node_id: node.node_id,
    private_key: node.privateKey,
    signed_at: new Date(signedAt).toISOString(),
    vote_store: f.voteStores[node.node_id],
  }));
}

function fenceProposal(f, overrides = {}) {
  return createFenceProposal({
    cluster: f.clusterInput,
    term: 1,
    leader_node_id: 'NODE:A',
    previous_fence_sha256: null,
    valid_from: new Date(NOW - 1000).toISOString(),
    valid_until: new Date(NOW + 240000).toISOString(),
    ...overrides,
  });
}

(() => {
  const f = fixture();
  const fence = fenceProposal(f);
  assert.equal(f.cluster.quorum, 2);
  assert.throws(() => signProposal({ proposal: fence, node_id: f.nodes[0].node_id, private_key: f.nodes[0].privateKey, signed_at: new Date(NOW).toISOString() }), /ha_vote_store_required_for_signature/);

  const quorumSigs = signatures(fence, f);
  assert.match(quorumSigs[0].vote_reservation_sha256, /^[0-9a-f]{64}$/);
  assert.equal(quorumSigs[0].vote_reservation_sha256, f.voteStores['NODE:A'].verify().rows[0].record_sha256);
  assert.match(quorumSigs[0].signed_payload_sha256, /^[0-9a-f]{64}$/);
  assert.equal(quorumSigs[0].cluster_sha256, f.cluster.cluster_sha256);

  assert.throws(() => verifyQuorumCertificate({ cluster: f.clusterInput, proposal: fence, signatures: [quorumSigs[0]], now: NOW }), /ha_quorum_not_met/);
  assert.throws(() => verifyQuorumCertificate({ cluster: f.clusterInput, proposal: fence, signatures: [quorumSigs[0], quorumSigs[0]], now: NOW }), /ha_duplicate_signature/);

  const timestampTamper = quorumSigs.map(sig => ({ ...sig }));
  timestampTamper[0].signed_at = new Date(NOW + 1000).toISOString();
  assert.throws(() => verifyQuorumCertificate({ cluster: f.clusterInput, proposal: fence, signatures: timestampTamper, now: NOW + 1000 }), /ha_signature_envelope_mismatch|ha_signature_payload_hash_mismatch|ha_signature_invalid/);

  const reservationTamper = quorumSigs.map(sig => ({ ...sig }));
  reservationTamper[0].vote_reservation_sha256 = H('f');
  assert.throws(() => verifyQuorumCertificate({ cluster: f.clusterInput, proposal: fence, signatures: reservationTamper, now: NOW }), /ha_signature_payload_hash_mismatch|ha_signature_invalid/);

  const committedFence = f.fenceStore.commit({ proposal: fence, signatures: quorumSigs, now: NOW });
  assert.equal(committedFence.record.term, 1);
  assert.equal(f.fenceStore.verify().verified, true);

  const splitBrain = fenceProposal(f, { leader_node_id: 'NODE:B' });
  assert.throws(() => signProposal({ proposal: splitBrain, node_id: f.nodes[0].node_id, private_key: f.nodes[0].privateKey, signed_at: new Date(NOW).toISOString(), vote_store: f.voteStores['NODE:A'] }), /ha_vote_equivocation_detected/);

  const commit1 = createCommitProposal({
    cluster: f.clusterInput, term: 1, leader_node_id: 'NODE:A', commit_index: 1, state_root_sha256: H('a'),
    fence_record_sha256: committedFence.record.record_sha256, previous_commit_sha256: null,
  });
  const commitSigs = signatures(commit1, f, 2, NOW + 1000);
  const committed = f.commitStore.commit({ proposal: commit1, signatures: commitSigs, now: NOW + 1000 });
  assert.equal(committed.record.commit_index, 1);
  assert.equal(f.commitStore.verify().verified, true);

  const conflictingCommit = createCommitProposal({
    cluster: f.clusterInput, term: 1, leader_node_id: 'NODE:A', commit_index: 1, state_root_sha256: H('b'),
    fence_record_sha256: committedFence.record.record_sha256, previous_commit_sha256: null,
  });
  assert.throws(() => signProposal({ proposal: conflictingCommit, node_id: f.nodes[0].node_id, private_key: f.nodes[0].privateKey, signed_at: new Date(NOW + 1000).toISOString(), vote_store: f.voteStores['NODE:A'] }), /ha_vote_equivocation_detected/);

  const gap = createCommitProposal({
    cluster: f.clusterInput, term: 1, leader_node_id: 'NODE:A', commit_index: 3, state_root_sha256: H('b'),
    fence_record_sha256: committedFence.record.record_sha256, previous_commit_sha256: committed.record.record_sha256,
  });
  assert.throws(() => f.commitStore.commit({ proposal: gap, signatures: signatures(gap, f, 2, NOW + 2000), now: NOW + 2000 }), /ha_commit_next_index_required/);

  const checkpoint = { schema: 'g-bank-sovereign-state-checkpoint/v2', state_root_sha256: H('a') };
  const audit = assessHAReadiness({ cluster: f.clusterInput, fenceStore: f.fenceStore, commitStore: f.commitStore, voteStores: f.voteStores, checkpoint, now: NOW + 2000 });
  assert.equal(audit.state, 'PASS');
  assert.equal(audit.voter_journal_store_count, 3);
  assert.equal(audit.durable_fence_signer_count, 2);
  assert.equal(audit.durable_commit_signer_count, 2);
  assert.match(audit.voter_journal_root_sha256, /^[0-9a-f]{64}$/);
  assert.equal(audit.distributed_network_verified, false);

  const missing = assessHAReadiness({ cluster: f.clusterInput, fenceStore: f.fenceStore, commitStore: f.commitStore, voteStores: {}, checkpoint, now: NOW + 2000 });
  assert.equal(missing.state, 'BLOCK');
  assert.ok(missing.reasons.includes('VOTE_STORE_MISSING:NODE:A'));
  assert.ok(missing.reasons.includes('FENCE_DURABLE_QUORUM_NOT_MET'));
  assert.ok(missing.reasons.includes('COMMIT_DURABLE_QUORUM_NOT_MET'));

  const mismatch = assessHAReadiness({ cluster: f.clusterInput, fenceStore: f.fenceStore, commitStore: f.commitStore, voteStores: f.voteStores, checkpoint: { ...checkpoint, state_root_sha256: H('c') }, now: NOW + 2000 });
  assert.equal(mismatch.state, 'BLOCK');
  assert.ok(mismatch.reasons.includes('CHECKPOINT_NOT_REPLICATED'));

  const stale = assessHAReadiness({ cluster: f.clusterInput, fenceStore: f.fenceStore, commitStore: f.commitStore, voteStores: f.voteStores, checkpoint, now: NOW + 130000, max_commit_age_ms: 120000 });
  assert.equal(stale.state, 'BLOCK');
  assert.ok(stale.reasons.includes('COMMIT_STALE'));

  const votePath = f.voteStores['NODE:A'].filePath;
  const voteRows = fs.readFileSync(votePath, 'utf8').trim().split('\n').map(JSON.parse);
  voteRows[0].proposal_sha256 = H('f');
  fs.writeFileSync(votePath, voteRows.map(JSON.stringify).join('\n') + '\n');
  assert.throws(() => f.voteStores['NODE:A'].verify(), /ha_vote_record_hash_mismatch/);
})();

(() => {
  const f = fixture();
  const fence = fenceProposal(f);
  f.fenceStore.commit({ proposal: fence, signatures: signatures(fence, f), now: NOW });
  const fenceFile = path.join(f.root, 'fences.jsonl');
  const rows = fs.readFileSync(fenceFile, 'utf8').trim().split('\n').map(JSON.parse);
  const row = rows[0];

  row.quorum_certificate.signatures[0].signature_base64 = Buffer.from('forged-signature').toString('base64');
  const { certificate_sha256: oldCertHash, ...certBody } = row.quorum_certificate;
  row.quorum_certificate.certificate_sha256 = sha256(canonicalJson(certBody));
  row.quorum_certificate_sha256 = row.quorum_certificate.certificate_sha256;
  const { record_sha256: oldRecordHash, ...recordBody } = row;
  row.record_sha256 = sha256(canonicalJson(recordBody));
  fs.writeFileSync(fenceFile, JSON.stringify(row) + '\n');

  assert.notEqual(row.quorum_certificate.certificate_sha256, oldCertHash);
  assert.notEqual(row.record_sha256, oldRecordHash);
  assert.throws(() => f.fenceStore.verify(), /ha_signature_invalid|ha_certificate_reverification_mismatch/);
})();

(() => {
  const f = fixture();
  const fence = fenceProposal(f);
  f.fenceStore.commit({ proposal: fence, signatures: signatures(fence, f), now: NOW });
  const fenceFile = path.join(f.root, 'fences.jsonl');
  const rows = fs.readFileSync(fenceFile, 'utf8').trim().split('\n').map(JSON.parse);
  const row = rows[0];

  row.quorum_certificate.signatures[0].signed_at = new Date(NOW + 5000).toISOString();
  const envelope = { ...row.quorum_certificate.signatures[0] };
  delete envelope.signed_payload_sha256;
  delete envelope.signature_base64;
  row.quorum_certificate.signatures[0].signed_payload_sha256 = sha256(canonicalJson(envelope));
  const { certificate_sha256, ...certBody } = row.quorum_certificate;
  row.quorum_certificate.certificate_sha256 = sha256(canonicalJson(certBody));
  row.quorum_certificate_sha256 = row.quorum_certificate.certificate_sha256;
  const { record_sha256, ...recordBody } = row;
  row.record_sha256 = sha256(canonicalJson(recordBody));
  fs.writeFileSync(fenceFile, JSON.stringify(row) + '\n');

  assert.throws(() => f.fenceStore.verify(), /ha_signature_invalid|ha_certificate_reverification_mismatch/);
})();

(() => {
  const f = fixture();
  const expired = fenceProposal(f, { valid_from: new Date(NOW - 300000).toISOString(), valid_until: new Date(NOW - 1).toISOString() });
  assert.throws(() => f.fenceStore.commit({ proposal: expired, signatures: signatures(expired, f), now: NOW }), /ha_fence_not_current/);
})();

console.log('G-BANK sovereign v2 HA quorum/fencing tests: PASS');
