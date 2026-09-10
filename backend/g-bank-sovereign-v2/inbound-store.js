'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');

const ALLOWED = {
  CLAIMED: new Set(['PENDING', 'REJECTED']),
  PENDING: new Set(['AVAILABLE', 'REJECTED']),
  AVAILABLE: new Set(),
  REJECTED: new Set(),
};

class InboundStore {
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
      catch { throw new Error(`inbound_store_corrupt_line_${index + 1}`); }
    });
  }

  _verifyRows(rows) {
    let previous = 'GENESIS';
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      if (row.sequence !== i + 1) throw new Error('inbound_store_sequence_invalid');
      if (row.previous_record_sha256 !== previous) throw new Error('inbound_store_hash_chain_broken');
      const supplied = row.record_sha256;
      const copy = { ...row };
      delete copy.record_sha256;
      if (sha256(canonicalJson(copy)) !== supplied) throw new Error('inbound_store_record_hash_mismatch');
      previous = supplied;
    }
    return Object.freeze({ verified: true, record_count: rows.length, head_sha256: previous });
  }

  verify() {
    return this._verifyRows(this._rows());
  }

  current(inboundId) {
    const id = String(inboundId || '').trim();
    if (!id) throw new Error('inbound_id_invalid');
    const rows = this._rows();
    this._verifyRows(rows);
    const matches = rows.filter(row => row.inbound_id === id);
    return matches.length ? Object.freeze({ ...matches[matches.length - 1] }) : null;
  }

  _withLock(fn) {
    let lockFd;
    try {
      lockFd = fs.openSync(this.lockPath, 'wx', 0o600);
    } catch (err) {
      if (err.code === 'EEXIST') throw new Error('inbound_store_busy');
      throw err;
    }
    try {
      return fn();
    } finally {
      try { fs.closeSync(lockFd); } catch {}
      try { fs.unlinkSync(this.lockPath); } catch {}
    }
  }

  _appendUnlocked(rows, body) {
    const proof = this._verifyRows(rows);
    const record = {
      schema: 'g-bank-inbound-state-record/v2',
      sequence: rows.length + 1,
      ...body,
      previous_record_sha256: proof.head_sha256,
    };
    record.record_sha256 = sha256(canonicalJson(record));
    const fd = fs.openSync(this.filePath, 'a', 0o600);
    try {
      fs.writeSync(fd, JSON.stringify(record) + '\n');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    return Object.freeze(record);
  }

  claim({ inbound_id, event_sha256, target_account_id, amount_minor, currency, now = Date.now() }) {
    const id = String(inbound_id || '').trim();
    if (!id || id.length > 256) throw new Error('inbound_id_invalid');
    const eventHash = String(event_sha256 || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(eventHash)) throw new Error('inbound_event_sha256_invalid');
    return this._withLock(() => {
      const rows = this._rows();
      this._verifyRows(rows);
      const matches = rows.filter(row => row.inbound_id === id);
      if (matches.length) {
        const existing = matches[matches.length - 1];
        if (existing.event_sha256 !== eventHash) throw new Error('inbound_id_reused_for_different_event');
        return Object.freeze({ owner: false, record: Object.freeze({ ...existing }) });
      }
      const record = this._appendUnlocked(rows, {
        inbound_id: id,
        state: 'CLAIMED',
        event_sha256: eventHash,
        target_account_id: String(target_account_id),
        amount_minor: Number(amount_minor),
        currency: String(currency).toUpperCase(),
        observed_at: new Date(now).toISOString(),
      });
      return Object.freeze({ owner: true, record });
    });
  }

  transition({ inbound_id, expected_state, to_state, evidence_sha256, ledger_record_sha256 = null, now = Date.now() }) {
    const id = String(inbound_id || '').trim();
    const expected = String(expected_state || '').toUpperCase();
    const next = String(to_state || '').toUpperCase();
    if (!ALLOWED[expected] || !ALLOWED[expected].has(next)) throw new Error('inbound_state_transition_invalid');
    const evidence = String(evidence_sha256 || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(evidence)) throw new Error('inbound_transition_evidence_sha256_invalid');
    const ledgerHash = ledger_record_sha256 === null ? null : String(ledger_record_sha256).toLowerCase();
    if (ledgerHash !== null && !/^[0-9a-f]{64}$/.test(ledgerHash)) throw new Error('inbound_ledger_record_sha256_invalid');

    return this._withLock(() => {
      const rows = this._rows();
      this._verifyRows(rows);
      const matches = rows.filter(row => row.inbound_id === id);
      if (!matches.length) throw new Error('inbound_state_missing');
      const current = matches[matches.length - 1];
      if (current.state !== expected) throw new Error('inbound_state_conflict');
      return this._appendUnlocked(rows, {
        inbound_id: id,
        state: next,
        event_sha256: current.event_sha256,
        target_account_id: current.target_account_id,
        amount_minor: current.amount_minor,
        currency: current.currency,
        transition_evidence_sha256: evidence,
        ledger_record_sha256: ledgerHash,
        observed_at: new Date(now).toISOString(),
      });
    });
  }
}

module.exports = { InboundStore };
