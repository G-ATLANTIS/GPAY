'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');

function hash64(name, value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}_invalid`);
  return hash;
}

class EvidenceRevocationStore {
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
      catch { throw new Error(`evidence_revocation_corrupt_line_${index + 1}`); }
    });
  }

  verify() {
    const rows = this._rows();
    let previous = 'GENESIS';
    const seen = new Set();
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      if (row.sequence !== i + 1) throw new Error('evidence_revocation_sequence_invalid');
      if (row.previous_record_sha256 !== previous) throw new Error('evidence_revocation_hash_chain_broken');
      if (seen.has(row.evidence_sha256)) throw new Error('evidence_revocation_duplicate');
      seen.add(row.evidence_sha256);
      const supplied = row.record_sha256;
      const copy = { ...row };
      delete copy.record_sha256;
      if (sha256(canonicalJson(copy)) !== supplied) throw new Error('evidence_revocation_record_hash_mismatch');
      previous = supplied;
    }
    return Object.freeze({ verified: true, record_count: rows.length, head_sha256: previous });
  }

  revoke({ evidence_sha256, revocation_evidence_sha256, reason, now = Date.now() }) {
    const target = hash64('revoked_evidence_sha256', evidence_sha256);
    const authority = hash64('revocation_evidence_sha256', revocation_evidence_sha256);
    const why = String(reason || '').trim();
    if (!why || why.length > 256) throw new Error('evidence_revocation_reason_invalid');

    let fd;
    try { fd = fs.openSync(this.lockPath, 'wx', 0o600); }
    catch (err) {
      if (err.code === 'EEXIST') throw new Error('evidence_revocation_store_busy');
      throw err;
    }
    try {
      const proof = this.verify();
      const rows = this._rows();
      const existing = rows.find(row => row.evidence_sha256 === target);
      if (existing) return Object.freeze({ ...existing });
      const record = {
        schema: 'g-bank-evidence-revocation/v2',
        sequence: rows.length + 1,
        evidence_sha256: target,
        revocation_evidence_sha256: authority,
        reason: why,
        revoked_at: new Date(now).toISOString(),
        previous_record_sha256: proof.head_sha256,
      };
      record.record_sha256 = sha256(canonicalJson(record));
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

  isRevoked(evidenceSha256) {
    const target = hash64('evidence_sha256', evidenceSha256);
    this.verify();
    return this._rows().some(row => row.evidence_sha256 === target);
  }

  list() {
    this.verify();
    return Object.freeze(this._rows().map(row => Object.freeze({ ...row })));
  }
}

module.exports = { EvidenceRevocationStore };
