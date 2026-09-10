'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');

function hash64(name, value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}_invalid`);
  return hash;
}

function verifyRecoveryAnchorRecord(record) {
  if (!record || record.schema !== 'g-bank-recovery-anchor/v2') throw new Error('recovery_anchor_record_required');
  if (!Number.isSafeInteger(Number(record.sequence)) || Number(record.sequence) <= 0) throw new Error('recovery_anchor_sequence_invalid');
  if (!Number.isSafeInteger(Number(record.generation)) || Number(record.generation) <= 0) throw new Error('recovery_anchor_generation_invalid');
  hash64('recovery_anchor_manifest_sha256', record.manifest_sha256);
  if (Number(record.generation) === 1) {
    if (record.previous_manifest_sha256 !== null) throw new Error('recovery_anchor_genesis_manifest_chain_invalid');
  } else {
    hash64('recovery_anchor_previous_manifest_sha256', record.previous_manifest_sha256);
  }
  hash64('recovery_anchor_state_root_sha256', record.checkpoint_state_root_sha256);
  hash64('recovery_anchor_evidence_sha256', record.evidence_sha256);
  if (record.previous_record_sha256 !== 'GENESIS') hash64('recovery_anchor_previous_record_sha256', record.previous_record_sha256);
  if (record.grants_external_rights !== false || record.permits_value_movement !== false) throw new Error('recovery_anchor_boundary_invalid');
  const anchored = Date.parse(record.anchored_at);
  if (!Number.isFinite(anchored)) throw new Error('recovery_anchor_time_invalid');
  const supplied = hash64('recovery_anchor_record_sha256', record.record_sha256);
  const copy = { ...record };
  delete copy.record_sha256;
  if (sha256(canonicalJson(copy)) !== supplied) throw new Error('recovery_anchor_record_hash_mismatch');
  return true;
}

class RecoveryAnchorStore {
  constructor(filePath) {
    this.filePath = path.resolve(filePath);
    this.lockPath = `${this.filePath}.lock`;
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
  }

  _rows() {
    if (!fs.existsSync(this.filePath)) return [];
    const text = fs.readFileSync(this.filePath, 'utf8').trim();
    if (!text) return [];
    return text.split('\n').map((line, index) => {
      try { return JSON.parse(line); }
      catch { throw new Error(`recovery_anchor_corrupt_line_${index + 1}`); }
    });
  }

  verify() {
    const rows = this._rows();
    let previousRecord = 'GENESIS';
    let priorGeneration = 0;
    let priorManifest = null;
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      verifyRecoveryAnchorRecord(row);
      if (row.sequence !== i + 1) throw new Error('recovery_anchor_sequence_invalid');
      if (row.previous_record_sha256 !== previousRecord) throw new Error('recovery_anchor_hash_chain_broken');
      if (row.generation !== priorGeneration + 1) throw new Error('recovery_anchor_generation_gap');
      if (row.previous_manifest_sha256 !== priorManifest) throw new Error('recovery_anchor_manifest_chain_broken');
      previousRecord = row.record_sha256;
      priorGeneration = row.generation;
      priorManifest = row.manifest_sha256;
    }
    return Object.freeze({
      verified: true,
      anchor_count: rows.length,
      latest_generation: priorGeneration,
      latest_manifest_sha256: priorManifest,
      head_sha256: previousRecord,
    });
  }

  commit({ generation, manifest_sha256, previous_manifest_sha256, checkpoint_state_root_sha256, evidence_sha256, now = Date.now() }) {
    const gen = Number(generation);
    if (!Number.isSafeInteger(gen) || gen <= 0) throw new Error('recovery_anchor_generation_invalid');
    const manifest = hash64('recovery_anchor_manifest_sha256', manifest_sha256);
    const priorManifest = previous_manifest_sha256 === null ? null : hash64('recovery_anchor_previous_manifest_sha256', previous_manifest_sha256);
    const stateRoot = hash64('recovery_anchor_state_root_sha256', checkpoint_state_root_sha256);
    const evidence = hash64('recovery_anchor_evidence_sha256', evidence_sha256);

    let fd;
    try { fd = fs.openSync(this.lockPath, 'wx', 0o600); }
    catch (err) {
      if (err.code === 'EEXIST') throw new Error('recovery_anchor_store_busy');
      throw err;
    }
    try {
      const proof = this.verify();
      if (gen !== proof.latest_generation + 1) throw new Error('recovery_anchor_next_generation_required');
      if (priorManifest !== proof.latest_manifest_sha256) throw new Error('recovery_anchor_previous_manifest_mismatch');
      const rows = this._rows();
      const record = {
        schema: 'g-bank-recovery-anchor/v2',
        sequence: rows.length + 1,
        generation: gen,
        manifest_sha256: manifest,
        previous_manifest_sha256: priorManifest,
        checkpoint_state_root_sha256: stateRoot,
        evidence_sha256: evidence,
        anchored_at: new Date(now).toISOString(),
        previous_record_sha256: proof.head_sha256,
        grants_external_rights: false,
        permits_value_movement: false,
      };
      record.record_sha256 = sha256(canonicalJson(record));
      verifyRecoveryAnchorRecord(record);
      const out = fs.openSync(this.filePath, 'a', 0o600);
      try {
        fs.writeSync(out, JSON.stringify(record) + '\n');
        fs.fsyncSync(out);
      } finally { fs.closeSync(out); }
      return Object.freeze(record);
    } finally {
      try { fs.closeSync(fd); } catch {}
      try { fs.unlinkSync(this.lockPath); } catch {}
    }
  }

  latest() {
    const proof = this.verify();
    if (!proof.anchor_count) return null;
    const rows = this._rows();
    const latest = rows[rows.length - 1];
    verifyRecoveryAnchorRecord(latest);
    return Object.freeze({ ...latest });
  }
}

module.exports = { RecoveryAnchorStore, verifyRecoveryAnchorRecord };
