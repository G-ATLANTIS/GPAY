'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');

const TRANSITIONS = {
  PROSPECT: new Set(['REVIEW']),
  REVIEW: new Set(['ACTIVE', 'REJECTED']),
  ACTIVE: new Set(['SUSPENDED']),
  SUSPENDED: new Set(['ACTIVE', 'CLOSED']),
  REJECTED: new Set(),
  CLOSED: new Set(),
};

function customerId(value) {
  const id = String(value || '').toUpperCase();
  if (!/^G:CUSTOMER-SUBJECT:[A-Z0-9_-]{3,96}$/.test(id)) throw new Error('customer_id_invalid');
  return id;
}

function hash64(name, value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}_invalid`);
  return hash;
}

class CustomerRegistry {
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
      catch { throw new Error(`customer_registry_corrupt_line_${index + 1}`); }
    });
  }

  _verifyRows(rows) {
    let previous = 'GENESIS';
    const latest = new Map();
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      if (row.sequence !== i + 1) throw new Error('customer_registry_sequence_invalid');
      if (row.previous_record_sha256 !== previous) throw new Error('customer_registry_hash_chain_broken');
      const supplied = String(row.record_sha256 || '').toLowerCase();
      const copy = { ...row };
      delete copy.record_sha256;
      if (sha256(canonicalJson(copy)) !== supplied) throw new Error('customer_registry_record_hash_mismatch');
      const prevForCustomer = latest.get(row.customer_id);
      if (row.customer_sequence !== (prevForCustomer ? prevForCustomer.customer_sequence + 1 : 1)) throw new Error('customer_sequence_invalid');
      if (prevForCustomer && row.subject_binding_sha256 !== prevForCustomer.subject_binding_sha256) throw new Error('customer_subject_binding_changed');
      latest.set(row.customer_id, row);
      previous = supplied;
    }
    return Object.freeze({ verified: true, record_count: rows.length, head_sha256: previous });
  }

  verify() {
    return this._verifyRows(this._rows());
  }

  _withLock(fn) {
    let fd;
    try { fd = fs.openSync(this.lockPath, 'wx', 0o600); }
    catch (err) {
      if (err.code === 'EEXIST') throw new Error('customer_registry_busy');
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
    const existing = rows.filter(r => r.customer_id === body.customer_id);
    const record = {
      schema: 'g-bank-customer-state-record/v2',
      sequence: rows.length + 1,
      customer_sequence: existing.length ? existing[existing.length - 1].customer_sequence + 1 : 1,
      ...body,
      previous_record_sha256: proof.head_sha256,
    };
    record.record_sha256 = sha256(canonicalJson(record));
    const file = fs.openSync(this.filePath, 'a', 0o600);
    try {
      fs.writeSync(file, JSON.stringify(record) + '\n');
      fs.fsyncSync(file);
    } finally { fs.closeSync(file); }
    return Object.freeze(record);
  }

  create({ customer_id, subject_binding_sha256, customer_type = 'NATURAL_PERSON', jurisdiction = null, now = Date.now() }) {
    const id = customerId(customer_id);
    const subject = hash64('subject_binding_sha256', subject_binding_sha256);
    const type = String(customer_type || '').toUpperCase();
    if (!['NATURAL_PERSON', 'LEGAL_ENTITY'].includes(type)) throw new Error('customer_type_invalid');
    const country = jurisdiction === null ? null : String(jurisdiction).toUpperCase();
    if (country !== null && !/^[A-Z]{2}$/.test(country)) throw new Error('customer_jurisdiction_invalid');
    return this._withLock(() => {
      const rows = this._rows();
      this._verifyRows(rows);
      if (rows.some(r => r.customer_id === id)) throw new Error('customer_id_exists');
      if (rows.some(r => r.subject_binding_sha256 === subject)) throw new Error('subject_binding_already_registered');
      return this._appendUnlocked(rows, {
        customer_id: id,
        subject_binding_sha256: subject,
        customer_type: type,
        jurisdiction: country,
        status: 'PROSPECT',
        decision_evidence_sha256: null,
        reason: null,
        observed_at: new Date(now).toISOString(),
      });
    });
  }

  get(idValue) {
    const id = customerId(idValue);
    const rows = this._rows();
    this._verifyRows(rows);
    const matches = rows.filter(r => r.customer_id === id);
    if (!matches.length) throw new Error('customer_not_found');
    return Object.freeze({ ...matches[matches.length - 1] });
  }

  list({ status = null } = {}) {
    const rows = this._rows();
    this._verifyRows(rows);
    const latest = new Map();
    for (const row of rows) latest.set(row.customer_id, row);
    const wanted = status ? String(status).toUpperCase() : null;
    return Object.freeze([...latest.values()]
      .filter(row => !wanted || row.status === wanted)
      .sort((a, b) => a.customer_id.localeCompare(b.customer_id))
      .map(row => Object.freeze({ ...row })));
  }

  transition({ customer_id, expected_status, to_status, decision_evidence_sha256, reason = null, now = Date.now() }) {
    const id = customerId(customer_id);
    const expected = String(expected_status || '').toUpperCase();
    const next = String(to_status || '').toUpperCase();
    if (!TRANSITIONS[expected] || !TRANSITIONS[expected].has(next)) throw new Error('customer_status_transition_invalid');
    const evidence = hash64('customer_decision_evidence_sha256', decision_evidence_sha256);
    return this._withLock(() => {
      const rows = this._rows();
      this._verifyRows(rows);
      const matches = rows.filter(r => r.customer_id === id);
      if (!matches.length) throw new Error('customer_not_found');
      const current = matches[matches.length - 1];
      if (current.status !== expected) throw new Error('customer_status_conflict');
      return this._appendUnlocked(rows, {
        customer_id: current.customer_id,
        subject_binding_sha256: current.subject_binding_sha256,
        customer_type: current.customer_type,
        jurisdiction: current.jurisdiction,
        status: next,
        decision_evidence_sha256: evidence,
        reason: reason ? String(reason).slice(0, 256) : null,
        observed_at: new Date(now).toISOString(),
      });
    });
  }
}

module.exports = { CustomerRegistry, customerId };
