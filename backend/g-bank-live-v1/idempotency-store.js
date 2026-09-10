'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');
const { durableReplaceFileSync, durableCreateFileSync } = require('./durable-write');

function safeName(key) {
  return sha256(String(key));
}

class IdempotencyStore {
  constructor(rootDir) {
    this.rootDir = path.resolve(rootDir);
    fs.mkdirSync(this.rootDir, { recursive: true, mode: 0o700 });
  }

  fileFor(key) {
    return path.join(this.rootDir, `${safeName(key)}.json`);
  }

  read(key) {
    const file = this.fileFor(key);
    try {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  claim({ key, request }) {
    if (!key) throw new Error('idempotency_key_required');
    const requestSha = sha256(canonicalJson(request));
    const file = this.fileFor(key);
    const record = {
      schema: 'g-bank-live-idempotency/v1',
      key_sha256: safeName(key),
      request_sha256: requestSha,
      state: 'PENDING',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      result: null,
    };

    try {
      // O_EXCL create + fsync of file and directory: once claim() returns
      // owner:true the PENDING marker has reached stable storage, so a crash
      // cannot lose the fact that this key is in-flight.
      durableCreateFileSync(file, JSON.stringify(record, null, 2) + '\n', { mode: 0o600 });
      return { owner: true, record };
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      const existing = this.read(key);
      if (!existing || existing.request_sha256 !== requestSha) {
        throw new Error('idempotency_key_reused_for_different_request');
      }
      return { owner: false, record: existing };
    }
  }

  finalize({ key, request, state, result }) {
    if (!['SUCCEEDED', 'FAILED_FINAL', 'UNKNOWN_REQUIRES_RECONCILIATION'].includes(state)) {
      throw new Error('idempotency_final_state_invalid');
    }
    const file = this.fileFor(key);
    const current = this.read(key);
    if (!current) throw new Error('idempotency_record_missing');
    const requestSha = sha256(canonicalJson(request));
    if (current.request_sha256 !== requestSha) throw new Error('idempotency_request_mismatch');

    const next = {
      ...current,
      state,
      updated_at: new Date().toISOString(),
      result: result ?? null,
    };
    // Temp write -> fsync -> atomic rename -> directory fsync. A completed
    // finalize survives a crash immediately after this call returns.
    durableReplaceFileSync(file, JSON.stringify(next, null, 2) + '\n', { mode: 0o600 });
    return next;
  }
}

module.exports = { IdempotencyStore };
