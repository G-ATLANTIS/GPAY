'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('./canonical');

const TRANSITIONS = {
  OPEN: new Set(['UNDER_REVIEW', 'CLOSED']),
  UNDER_REVIEW: new Set(['ESCALATED', 'CLOSED']),
  ESCALATED: new Set(['CLOSED']),
  CLOSED: new Set(),
};

function hash64(name, value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}_invalid`);
  return hash;
}

class MonitoringCaseStore {
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
      catch { throw new Error(`monitoring_case_corrupt_line_${index + 1}`); }
    });
  }

  _verifyRows(rows) {
    let previous = 'GENESIS';
    const latest = new Map();
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      if (row.sequence !== i + 1) throw new Error('monitoring_case_sequence_invalid');
      if (row.previous_record_sha256 !== previous) throw new Error('monitoring_case_hash_chain_broken');
      const supplied = String(row.record_sha256 || '').toLowerCase();
      const copy = { ...row };
      delete copy.record_sha256;
      if (sha256(canonicalJson(copy)) !== supplied) throw new Error('monitoring_case_record_hash_mismatch');
      const prev = latest.get(row.case_id);
      if (row.case_sequence !== (prev ? prev.case_sequence + 1 : 1)) throw new Error('monitoring_case_local_sequence_invalid');
      latest.set(row.case_id, row);
      previous = supplied;
    }
    return Object.freeze({ verified: true, record_count: rows.length, head_sha256: previous });
  }

  verify() { return this._verifyRows(this._rows()); }

  _withLock(fn) {
    let fd;
    try { fd = fs.openSync(this.lockPath, 'wx', 0o600); }
    catch (err) {
      if (err.code === 'EEXIST') throw new Error('monitoring_case_store_busy');
      throw err;
    }
    try { return fn(); }
    finally {
      try { fs.closeSync(fd); } catch {}
      try { fs.unlinkSync(this.lockPath); } catch {}
    }
  }

  _appendUnlocked(rows, body) {
    const proof = this._verifyRows(rows);
    const prior = rows.filter(row => row.case_id === body.case_id);
    const record = {
      schema: 'g-bank-monitoring-case-record/v2',
      sequence: rows.length + 1,
      case_sequence: prior.length ? prior[prior.length - 1].case_sequence + 1 : 1,
      ...body,
      previous_record_sha256: proof.head_sha256,
    };
    record.record_sha256 = sha256(canonicalJson(record));
    const out = fs.openSync(this.filePath, 'a', 0o600);
    try {
      fs.writeSync(out, JSON.stringify(record) + '\n');
      fs.fsyncSync(out);
    } finally { fs.closeSync(out); }
    return Object.freeze(record);
  }

  open({ customer_id, signal_sha256, severity = 'MEDIUM', reason_code, now = Date.now(), case_id = null }) {
    const customer = String(customer_id || '').trim();
    if (!customer) throw new Error('monitoring_case_customer_id_invalid');
    const signal = hash64('monitoring_signal_sha256', signal_sha256);
    const level = String(severity || '').toUpperCase();
    if (!['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(level)) throw new Error('monitoring_case_severity_invalid');
    const reason = String(reason_code || '').toUpperCase();
    if (!/^[A-Z0-9_:-]{3,128}$/.test(reason)) throw new Error('monitoring_case_reason_invalid');
    const id = case_id ? String(case_id) : `GCASE:${crypto.randomUUID()}`;

    return this._withLock(() => {
      const rows = this._rows();
      this._verifyRows(rows);
      if (rows.some(row => row.case_id === id)) throw new Error('monitoring_case_id_exists');
      return this._appendUnlocked(rows, {
        case_id: id,
        customer_id: customer,
        status: 'OPEN',
        severity: level,
        reason_code: reason,
        signal_sha256: signal,
        decision_evidence_sha256: null,
        regulatory_suspicion_determined: false,
        external_report_submitted: false,
        observed_at: new Date(now).toISOString(),
      });
    });
  }

  transition({ case_id, expected_status, to_status, decision_evidence_sha256, now = Date.now() }) {
    const id = String(case_id || '').trim();
    const expected = String(expected_status || '').toUpperCase();
    const next = String(to_status || '').toUpperCase();
    if (!TRANSITIONS[expected] || !TRANSITIONS[expected].has(next)) throw new Error('monitoring_case_transition_invalid');
    const evidence = hash64('monitoring_case_decision_evidence_sha256', decision_evidence_sha256);

    return this._withLock(() => {
      const rows = this._rows();
      this._verifyRows(rows);
      const matches = rows.filter(row => row.case_id === id);
      if (!matches.length) throw new Error('monitoring_case_not_found');
      const current = matches[matches.length - 1];
      if (current.status !== expected) throw new Error('monitoring_case_status_conflict');
      return this._appendUnlocked(rows, {
        case_id: current.case_id,
        customer_id: current.customer_id,
        status: next,
        severity: current.severity,
        reason_code: current.reason_code,
        signal_sha256: current.signal_sha256,
        decision_evidence_sha256: evidence,
        regulatory_suspicion_determined: false,
        external_report_submitted: false,
        observed_at: new Date(now).toISOString(),
      });
    });
  }

  list({ customer_id = null, status = null } = {}) {
    const rows = this._rows();
    this._verifyRows(rows);
    const latest = new Map();
    for (const row of rows) latest.set(row.case_id, row);
    return Object.freeze([...latest.values()]
      .filter(row => !customer_id || row.customer_id === customer_id)
      .filter(row => !status || row.status === String(status).toUpperCase())
      .sort((a, b) => a.case_id.localeCompare(b.case_id))
      .map(row => Object.freeze({ ...row })));
  }
}

module.exports = { MonitoringCaseStore };
