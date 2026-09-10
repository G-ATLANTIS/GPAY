'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');
const { normalizeCluster, verifyQuorumCertificate } = require('./ha-quorum');

function appendLocked(filePath, lockPath, record) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  let lock;
  try { lock = fs.openSync(lockPath, 'wx', 0o600); }
  catch (err) { if (err.code === 'EEXIST') throw new Error('ha_store_busy'); throw err; }
  try {
    const fd = fs.openSync(filePath, 'a', 0o600);
    try { fs.writeSync(fd, JSON.stringify(record) + '\n'); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
  } finally {
    try { fs.closeSync(lock); } catch {}
    try { fs.unlinkSync(lockPath); } catch {}
  }
}

function rows(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const text = fs.readFileSync(filePath, 'utf8').trim();
  if (!text) return [];
  return text.split('\n').map((line, i) => { try { return JSON.parse(line); } catch { throw new Error(`ha_store_corrupt_line_${i + 1}`); } });
}

class HAFenceStore {
  constructor(filePath, cluster) {
    this.filePath = path.resolve(filePath);
    this.lockPath = `${this.filePath}.lock`;
    this.cluster = normalizeCluster(cluster);
  }

  verify() {
    const list = rows(this.filePath);
    let prior = null;
    let term = 0;
    for (let i = 0; i < list.length; i += 1) {
      const row = list[i];
      if (row.schema !== 'g-bank-ha-fence-record/v2' || row.sequence !== i + 1) throw new Error('ha_fence_record_invalid');
      if (row.term !== term + 1) throw new Error('ha_fence_term_not_monotonic');
      if (row.previous_fence_sha256 !== prior) throw new Error('ha_fence_chain_broken');
      const supplied = row.record_sha256;
      const copy = { ...row }; delete copy.record_sha256;
      if (sha256(canonicalJson(copy)) !== supplied) throw new Error('ha_fence_record_hash_mismatch');
      prior = supplied; term = row.term;
    }
    return Object.freeze({ verified: true, count: list.length, latest_term: term, latest_fence_sha256: prior, latest: list.length ? Object.freeze({ ...list[list.length - 1] }) : null });
  }

  commit({ proposal, signatures, now = Date.now() }) {
    const proof = this.verify();
    if (proposal.schema !== 'g-bank-ha-fence-proposal/v2') throw new Error('ha_fence_proposal_required');
    if (proposal.term !== proof.latest_term + 1) throw new Error('ha_fence_next_term_required');
    if (proposal.previous_fence_sha256 !== proof.latest_fence_sha256) throw new Error('ha_fence_previous_mismatch');
    if (Date.parse(proposal.valid_from) > now + 30000 || Date.parse(proposal.valid_until) <= now) throw new Error('ha_fence_not_current');
    const certificate = verifyQuorumCertificate({ cluster: this.cluster, proposal, signatures, now });
    const record = {
      schema: 'g-bank-ha-fence-record/v2',
      sequence: proof.count + 1,
      term: proposal.term,
      leader_node_id: proposal.leader_node_id,
      cluster_sha256: this.cluster.cluster_sha256,
      proposal_sha256: proposal.proposal_sha256,
      quorum_certificate_sha256: certificate.certificate_sha256,
      valid_from: proposal.valid_from,
      valid_until: proposal.valid_until,
      previous_fence_sha256: proof.latest_fence_sha256,
      committed_at: new Date(now).toISOString(),
      grants_external_rights: false,
      permits_value_movement_by_itself: false,
    };
    record.record_sha256 = sha256(canonicalJson(record));
    appendLocked(this.filePath, this.lockPath, record);
    return Object.freeze({ record: Object.freeze(record), certificate });
  }
}

class HACommitStore {
  constructor(filePath, cluster, fenceStore) {
    this.filePath = path.resolve(filePath);
    this.lockPath = `${this.filePath}.lock`;
    this.cluster = normalizeCluster(cluster);
    this.fenceStore = fenceStore;
  }

  verify() {
    const list = rows(this.filePath);
    let prior = null;
    let index = 0;
    for (let i = 0; i < list.length; i += 1) {
      const row = list[i];
      if (row.schema !== 'g-bank-ha-commit-record/v2' || row.commit_index !== index + 1) throw new Error('ha_commit_index_invalid');
      if (row.previous_commit_sha256 !== prior) throw new Error('ha_commit_chain_broken');
      const supplied = row.record_sha256;
      const copy = { ...row }; delete copy.record_sha256;
      if (sha256(canonicalJson(copy)) !== supplied) throw new Error('ha_commit_record_hash_mismatch');
      prior = supplied; index = row.commit_index;
    }
    return Object.freeze({ verified: true, count: list.length, latest_commit_index: index, latest_commit_sha256: prior, latest: list.length ? Object.freeze({ ...list[list.length - 1] }) : null });
  }

  commit({ proposal, signatures, now = Date.now() }) {
    const commits = this.verify();
    const fence = this.fenceStore.verify().latest;
    if (!fence) throw new Error('ha_active_fence_required');
    if (Date.parse(fence.valid_until) <= now || Date.parse(fence.valid_from) > now) throw new Error('ha_fence_expired_or_not_started');
    if (proposal.schema !== 'g-bank-ha-commit-proposal/v2') throw new Error('ha_commit_proposal_required');
    if (proposal.term !== fence.term || proposal.leader_node_id !== fence.leader_node_id || proposal.fence_record_sha256 !== fence.record_sha256) throw new Error('ha_commit_fence_mismatch');
    if (proposal.commit_index !== commits.latest_commit_index + 1 || proposal.previous_commit_sha256 !== commits.latest_commit_sha256) throw new Error('ha_commit_next_index_required');
    const certificate = verifyQuorumCertificate({ cluster: this.cluster, proposal, signatures, now });
    const record = {
      schema: 'g-bank-ha-commit-record/v2',
      commit_index: proposal.commit_index,
      term: proposal.term,
      leader_node_id: proposal.leader_node_id,
      cluster_sha256: this.cluster.cluster_sha256,
      state_root_sha256: proposal.state_root_sha256,
      fence_record_sha256: proposal.fence_record_sha256,
      proposal_sha256: proposal.proposal_sha256,
      quorum_certificate_sha256: certificate.certificate_sha256,
      previous_commit_sha256: commits.latest_commit_sha256,
      committed_at: new Date(now).toISOString(),
      grants_external_rights: false,
      permits_value_movement_by_itself: false,
    };
    record.record_sha256 = sha256(canonicalJson(record));
    appendLocked(this.filePath, this.lockPath, record);
    return Object.freeze({ record: Object.freeze(record), certificate });
  }
}

module.exports = { HAFenceStore, HACommitStore };
