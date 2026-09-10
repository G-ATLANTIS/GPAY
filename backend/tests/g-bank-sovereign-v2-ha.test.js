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
  const voteStores = Object.fromEntries(nodes.map(node => [node.node_id, new HAVoteStore(path.join(root, `votes-${node.node_id.replace(':', '-')}.jsonl`), { node_id: node.node_id })]));
  return { root, nodes, clusterInput, cluster, fenceStore, commitStore, voteStores };
}

function signatures(proposal, nodes, count = 2, voteStores = null, signedAt = NOW) {
  return nodes.slice(0, count).map(node => signProposal({
    proposal,
    node_id: node.node_id,
    private_key: node.privateKey,
    signed_at: new Date(signedAt).toISOString(),
    vote_store: voteStores ? voteStores[node.node_id] : null,
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
  assert.equal(f.cluster.quorum, 2);
  const fence = fenceProposal(f);
  const quorumSigs = signatures(fence, f.nodes, 2, f.voteStores);

  assert.match(quorumSigs[0].signed_payload_sha256, /^[0-9a-f]{64}$/);
  assert.equal(quorumSigs[0].cluster_sha256, f.cluster.cluster_sha256);
  assert.equal(quorumSigs[0].cluster_epoch, 1);
  assert.equal(quorumSigs[0].proposal_sha256, fence.proposal_sha256);
  assert.equal(quorumSigs[0].proposal_schema, fence.schema);

  assert.throws(() => verifyQuorumCertificate({ cluster: f.clusterInput, proposal: fence, signatures: [quorumSigs[0]], now: NOW }), /ha_quorum_not_met/);
  assert.throws(() => verifyQuorumCertificate({ cluster: f.clusterInput, proposal: fence, signatures: [quorumSigs[0], quorumSigs[0]], now: NOW }), /ha_duplicate_signature/);

  const timestampTamper = quorumSigs.map(sig => ({ ...sig }));
  timestampTamper[0].signed_at = new Date(NOW + 1000).toISOString();
  assert.throws(() => verifyQuorumCertificate({ cluster: f.clusterInput, proposal: fence, signatures: timestampTamper, now: NOW + 1000 }), /ha_signature_envelope_mismatch:signed_at|ha_signature_payload_hash_mismatch|ha_signature_invalid/);

  const nodeTamper = quorumSigs.map(sig => ({ ...sig }));
  nodeTamper[0].node_id = 'NODE:C';
  assert.throws(() => verifyQuorumCertificate({ cluster: f.clusterInput, proposal: fence, signatures: nodeTamper, now: NOW }), /ha_duplicate_signature|ha_signature_envelope_mismatch|ha_signature_invalid/);

  const committedFence = f.fenceStore.commit({ proposal: fence, signatures: quorumSigs, now: NOW });
  assert.equal(committedFence.record.term, 1);
  assert.equal(committedFence.record.leader_node_id, 'NODE:A');
  assert.equal(f.fenceStore.verify().verified, true);

  const splitBrain = fenceProposal(f, { term: 1, leader_node_id: 'NODE:B' });
  assert.throws(() => signProposal({
    proposal: splitBrain,
    node_id: f.nodes[0].node_id,
    private_key: f.nodes[0].privateKey,
    signed_at: new Date(NOW).toISOString(),
    vote_store: f.voteStores[f.nodes[0].node_id],
  }), /ha_vote_equivocation_detected/);

  const commit1 = createCommitProposal({
    cluster: f.clusterInput,
    term: 1,
    leader_node_id: 'NODE:A',
    commit_index: 1,
    state_root_sha256: H('a'),
    fence_record_sha256: committedFence.record.record_sha256,
    previous_commit_sha256: null,
  });
  const commitSigs = signatures(commit1, f.nodes, 2, f.voteStores, NOW + 1000);
  const committed = f.commitStore.commit({ proposal: commit1, signatures: commitSigs, now: NOW + 1000 });
  assert.equal(committed.record.commit_index, 1);
  assert.equal(f.commitStore.verify().verified, true);

  const conflictingCommit = createCommitProposal({
    cluster: f.clusterInput,
    term: 1,
    leader_node_id: 'NODE:A',
    commit_index: 1,
    state_root_sha256: H('b'),
    fence_record_sha256: committedFence.record.record_sha256,
    previous_commit_sha256: null,
  });
  assert.throws(() => signProposal({
    proposal: conflictingCommit,
    node_id: f.nodes[0].node_id,
    private_key: f.nodes[0].privateKey,
    signed_at: new Date(NOW + 1000).toISOString(),
    vote_store: f.voteStores[f.nodes[0].node_id],
  }), /ha_vote_equivocation_detected/);

  assert.throws(() => f.commitStore.commit({ proposal: commit1, signatures: commitSigs, now: NOW + 2000 }), /ha_commit_next_index_required/);

  const gap = createCommitProposal({
    cluster: f.clusterInput,
    term: 1,
    leader_node_id: 'NODE:A',
    commit_index: 3,
    state_root_sha256: H('b'),
    fence_record_sha256: committedFence.record.record_sha256,
    previous_commit_sha256: committed.record.record_sha256,
  });
  assert.throws(() => f.commitStore.commit({ proposal: gap, signatures: signatures(gap, f.nodes, 2, null, NOW + 2000), now: NOW + 2000 }), /ha_commit_next_index_required/);

  const checkpoint = { schema: 'g-bank-sovereign-state-checkpoint/v2', state_root_sha256: H('a') };
  const audit = assessHAReadiness({ cluster: f.clusterInput, fenceStore: f.fenceStore, commitStore: f.commitStore, voteStores: f.voteStores, checkpoint, now: NOW + 2000 });
  assert.equal(audit.state, 'PASS');
  assert.equal(audit.latest_commit_index, 1);
  assert.equal(audit.distributed_network_verified, false);
  assert.equal(audit.grants_external_rights, false);
  assert.match(audit.voter_journal_root_sha256, /^[0-9a-f]{64}$/);
  assert.match(audit.voter_journal_heads['NODE:A'], /^[0-9a-f]{64}$/);
  assert.match(audit.voter_journal_heads['NODE:B'], /^[0-9a-f]{64}$/);
  assert.equal(audit.voter_journal_heads['NODE:C'], null);
  assert.match(audit.audit_sha256, /^[0-9a-f]{64}$/);

  const missingJournals = assessHAReadiness({ cluster: f.clusterInput, fenceStore: f.fenceStore, commitStore: f.commitStore, voteStores: {}, checkpoint, now: NOW + 2000 });
  assert.equal(missingJournals.state, 'BLOCK');
  assert.ok(missingJournals.reasons.includes('VOTE_STORE_MISSING:NODE:A'));
  assert.ok(missingJournals.reasons.includes('FENCE_SIGNER_VOTE_NOT_DURABLE:NODE:A'));

  const onlyA = { 'NODE:A': f.voteStores['NODE:A'] };
  const partialJournals = assessHAReadiness({ cluster: f.clusterInput, fenceStore: f.fenceStore, commitStore: f.commitStore, voteStores: onlyA, checkpoint, now: NOW + 2000 });
  assert.equal(partialJournals.state, 'BLOCK');
  assert.ok(partialJournals.reasons.includes('VOTE_STORE_MISSING:NODE:B'));
  assert.ok(partialJournals.reasons.includes('COMMIT_SIGNER_VOTE_NOT_DURABLE:NODE:B'));

  const mismatch = assessHAReadiness({ cluster: f.clusterInput, fenceStore: f.fenceStore, commitStore: f.commitStore, voteStores: f.voteStores, checkpoint: { ...checkpoint, state_root_sha256: H('c') }, now: NOW + 2000 });
  assert.equal(mismatch.state, 'BLOCK');
  assert.ok(mismatch.reasons.includes('CHECKPOINT_NOT_REPLICATED'));

  const stale = assessHAReadiness({ cluster: f.clusterInput, fenceStore: f.fenceStore, commitStore: f.commitStore, voteStores: f.voteStores, checkpoint, now: NOW + 130000, max_commit_age_ms: 120000 });
  assert.equal(stale.state, 'BLOCK');
  assert.ok(stale.reasons.includes('COMMIT_STALE'));

  for (const store of Object.values(f.voteStores)) assert.equal(store.verify().verified, true);

  const votePath = f.voteStores['NODE:A'].filePath;
  const voteRows = fs.readFileSync(votePath, 'utf8').trim().split('\n').map(JSON.parse);
  voteRows[0].proposal_sha256 = H('f');
  fs.writeFileSync(votePath, voteRows.map(JSON.stringify).join('\n') + '\n');
  assert.throws(() => f.voteStores['NODE:A'].verify(), /ha_vote_record_hash_mismatch/);
})();

(() => {
  const f = fixture();
  const fence = fenceProposal(f);
  f.fenceStore.commit({ proposal: fence, signatures: signatures(fence, f.nodes), now: NOW });
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
  f.fenceStore.commit({ proposal: fence, signatures: signatures(fence, f.nodes), now: NOW });
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
  assert.throws(() => f.fenceStore.commit({ proposal: expired, signatures: signatures(expired, f.nodes), now: NOW }), /ha_fence_not_current/);
})();

console.log('G-BANK sovereign v2 HA quorum/fencing tests: PASS');
