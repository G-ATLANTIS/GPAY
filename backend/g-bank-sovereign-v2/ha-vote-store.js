'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');

function hash64(name, value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}_invalid`);
  return hash;
}

function positiveInt(name, value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 1) throw new Error(`${name}_invalid`);
  return n;
}

function nodeId(value) {
  const id = String(value || '').toUpperCase();
  if (!/^[A-Z0-9:_-]{3,96}$/.test(id)) throw new Error('ha_vote_node_id_invalid');
  return id;
}

function proposalSlot(p) {
  if (p?.schema === 'g-bank-ha-fence-proposal/v2') {
    return `FENCE:${positiveInt('ha_vote_cluster_epoch', p.cluster_epoch)}:${positiveInt('ha_vote_term', p.term)}`;
  }
  if (p?.schema === 'g-bank-ha-commit-proposal/v2') {
    return `COMMIT:${positiveInt('ha_vote_cluster_epoch', p.cluster_epoch)}:${positiveInt('ha_vote_term', p.term)}:${positiveInt('ha_vote_commit_index', p.commit_index)}`;
  }
  throw new Error('ha_vote_proposal_invalid');
}

function readRows(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('ha_vote_store_file_invalid');
  const text = fs.readFileSync(filePath, 'utf8').trim();
  if (!text) return [];
  return text.split('\n').map((line, i) => {
    try { return JSON.parse(line); }
    catch { throw new Error(`ha_vote_store_corrupt_line_${i + 1}`); }
  });
}

function withLock(lockPath, fn) {
  fs.mkdirSync(path.dirname(lockPath), { recursive: true, mode: 0o700 });
  let fd;
  try { fd = fs.openSync(lockPath, 'wx', 0o600); }
  catch (err) { if (err.code === 'EEXIST') throw new Error('ha_vote_store_busy'); throw err; }
  try { return fn(); }
  finally {
    try { fs.closeSync(fd); } catch {}
    try { fs.unlinkSync(lockPath); } catch {}
  }
}

class HAVoteStore {
  constructor(filePath, { node_id } = {}) {
    this.filePath = path.resolve(String(filePath || ''));
    if (!filePath) throw new Error('ha_vote_store_path_required');
    this.lockPath = `${this.filePath}.lock`;
    this.nodeId = nodeId(node_id);
  }

  verify() {
    const rows = readRows(this.filePath);
    let prior = null;
    const slots = new Map();
    const epochCluster = new Map();
    const maxTermByEpoch = new Map();
    let maxClusterEpoch = 0;

    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      if (row?.schema !== 'g-bank-ha-vote-reservation/v2' || row.sequence !== i + 1) throw new Error('ha_vote_record_invalid');
      if (row.node_id !== this.nodeId) throw new Error('ha_vote_record_node_mismatch');
      if (row.previous_record_sha256 !== prior) throw new Error('ha_vote_chain_broken');
      const supplied = hash64('ha_vote_record_sha256', row.record_sha256);
      const copy = { ...row }; delete copy.record_sha256;
      if (sha256(canonicalJson(copy)) !== supplied) throw new Error('ha_vote_record_hash_mismatch');

      const epoch = positiveInt('ha_vote_record_cluster_epoch', row.cluster_epoch);
      const clusterHash = hash64('ha_vote_record_cluster_sha256', row.cluster_sha256);
      if (epoch < maxClusterEpoch) throw new Error('ha_vote_cluster_epoch_rollback_record');
      if (epochCluster.has(epoch) && epochCluster.get(epoch) !== clusterHash) throw new Error('ha_vote_cluster_changed_without_epoch_bump');
      epochCluster.set(epoch, clusterHash);
      maxClusterEpoch = Math.max(maxClusterEpoch, epoch);

      const expectedSlot = proposalSlot({ schema: row.proposal_schema, cluster_epoch: epoch, term: row.term, commit_index: row.commit_index });
      if (row.slot_key !== expectedSlot) throw new Error('ha_vote_slot_mismatch');
      if (slots.has(row.slot_key)) throw new Error('ha_vote_duplicate_slot_record');
      slots.set(row.slot_key, row);

      const term = positiveInt('ha_vote_record_term', row.term);
      const priorMaxTerm = maxTermByEpoch.get(epoch) || 0;
      if (term < priorMaxTerm) throw new Error('ha_vote_term_rollback_record');
      maxTermByEpoch.set(epoch, Math.max(priorMaxTerm, term));
      prior = supplied;
    }

    return Object.freeze({
      verified: true,
      count: rows.length,
      latest_record_sha256: prior,
      max_cluster_epoch: maxClusterEpoch,
      epoch_cluster_sha256: Object.freeze(Object.fromEntries([...epochCluster.entries()].map(([epoch, hash]) => [String(epoch), hash]))),
      max_term_by_epoch: Object.freeze(Object.fromEntries([...maxTermByEpoch.entries()].map(([epoch, term]) => [String(epoch), term]))),
      rows: Object.freeze(rows.map(row => Object.freeze({ ...row }))),
    });
  }

  reserve({ proposal, node_id, signer_key_binding_sha256, signed_at }) {
    const requestedNode = nodeId(node_id);
    if (requestedNode !== this.nodeId) throw new Error('ha_vote_store_node_mismatch');
    const p = proposal;
    const slotKey = proposalSlot(p);
    const proposalHash = hash64('ha_vote_proposal_sha256', p.proposal_sha256);
    const clusterHash = hash64('ha_vote_cluster_sha256', p.cluster_sha256);
    const keyHash = hash64('ha_vote_signer_key_binding_sha256', signer_key_binding_sha256);
    const epoch = positiveInt('ha_vote_cluster_epoch', p.cluster_epoch);
    const term = positiveInt('ha_vote_term', p.term);
    const signedAtMs = Date.parse(signed_at);
    if (!Number.isFinite(signedAtMs)) throw new Error('ha_vote_signed_at_invalid');
    const signedAt = new Date(signedAtMs).toISOString();

    return withLock(this.lockPath, () => {
      const verified = this.verify();
      const existing = verified.rows.find(row => row.slot_key === slotKey);
      if (existing) {
        if (existing.proposal_sha256 !== proposalHash) throw new Error('ha_vote_equivocation_detected');
        if (existing.signer_key_binding_sha256 !== keyHash || existing.signed_at !== signedAt) throw new Error('ha_vote_replay_envelope_mismatch');
        return existing;
      }

      if (epoch < verified.max_cluster_epoch) throw new Error('ha_vote_cluster_epoch_rollback');
      const knownClusterHash = verified.epoch_cluster_sha256[String(epoch)] || null;
      if (knownClusterHash && knownClusterHash !== clusterHash) throw new Error('ha_vote_cluster_changed_without_epoch_bump');
      const maxTerm = Number(verified.max_term_by_epoch[String(epoch)] || 0);
      if (term < maxTerm) throw new Error('ha_vote_term_rollback');

      const record = {
        schema: 'g-bank-ha-vote-reservation/v2',
        sequence: verified.count + 1,
        node_id: this.nodeId,
        cluster_sha256: clusterHash,
        cluster_epoch: epoch,
        proposal_schema: p.schema,
        slot_key: slotKey,
        term,
        commit_index: p.schema === 'g-bank-ha-commit-proposal/v2' ? positiveInt('ha_vote_commit_index', p.commit_index) : null,
        proposal_sha256: proposalHash,
        signer_key_binding_sha256: keyHash,
        signed_at: signedAt,
        previous_record_sha256: verified.latest_record_sha256,
        grants_external_rights: false,
        permits_value_movement_by_itself: false,
      };
      record.record_sha256 = sha256(canonicalJson(record));
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
      const fd = fs.openSync(this.filePath, 'a', 0o600);
      try { fs.writeSync(fd, JSON.stringify(record) + '\n'); fs.fsyncSync(fd); }
      finally { fs.closeSync(fd); }
      return Object.freeze({ ...record });
    });
  }
}

module.exports = { HAVoteStore, proposalSlot };
