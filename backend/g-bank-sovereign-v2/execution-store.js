'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-live-v1/canonical');

const TRANSITIONS = Object.freeze({
  CLAIMED: new Set(['HELD', 'FAILED_FINAL']),
  HELD: new Set(['SUBMITTED', 'REJECTED', 'UNKNOWN']),
  SUBMITTED: new Set(['PENDING_SETTLEMENT', 'SETTLED', 'REJECTED', 'UNKNOWN']),
  PENDING_SETTLEMENT: new Set(['SETTLED', 'REJECTED', 'UNKNOWN']),
  UNKNOWN: new Set(['PENDING_SETTLEMENT', 'SETTLED', 'REJECTED']),
  SETTLED: new Set(),
  REJECTED: new Set(),
  FAILED_FINAL: new Set(),
});

class SovereignExecutionStore {
  constructor(rootDir) {
    this.rootDir = path.resolve(rootDir);
    fs.mkdirSync(this.rootDir, { recursive: true, mode: 0o700 });
  }

  _file(key) {
    return path.join(this.rootDir, `${sha256(String(key))}.json`);
  }

  read(key) {
    try { return JSON.parse(fs.readFileSync(this._file(key), 'utf8')); }
    catch (err) { if (err.code === 'ENOENT') return null; throw err; }
  }

  claim({ key, request }) {
    if (!key) throw new Error('idempotency_key_required');
    const requestSha = sha256(canonicalJson(request));
    const record = {
      schema: 'g-bank-sovereign-execution-state/v2',
      key_sha256: sha256(String(key)),
      request_sha256: requestSha,
      state: 'CLAIMED',
      result: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    try {
      fs.writeFileSync(this._file(key), JSON.stringify(record, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
      return { owner: true, record };
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      const existing = this.read(key);
      if (!existing || existing.request_sha256 !== requestSha) throw new Error('idempotency_key_reused_for_different_request');
      return { owner: false, record: existing };
    }
  }

  transition({ key, request, to, result = null }) {
    if (!TRANSITIONS[to]) throw new Error('execution_state_invalid');
    const file = this._file(key);
    const current = this.read(key);
    if (!current) throw new Error('execution_state_missing');
    if (current.request_sha256 !== sha256(canonicalJson(request))) throw new Error('execution_request_mismatch');
    const allowed = TRANSITIONS[current.state];
    if (!allowed || !allowed.has(to)) throw new Error(`execution_transition_forbidden_${current.state}_to_${to}`);
    const next = { ...current, state: to, result, updated_at: new Date().toISOString() };
    const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(next, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    fs.renameSync(tmp, file);
    return next;
  }
}

module.exports = { SovereignExecutionStore, TRANSITIONS };
