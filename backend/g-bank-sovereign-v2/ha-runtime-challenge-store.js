'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');

function hash64(name, value) {
  const v = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) throw new Error(`${name}_invalid`);
  return v;
}

function rows(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('ha_runtime_challenge_store_file_invalid');
  const text = fs.readFileSync(filePath, 'utf8').trim();
  if (!text) return [];
  return text.split('\n').map((line, i) => {
    try { return JSON.parse(line); }
    catch { throw new Error(`ha_runtime_challenge_store_corrupt_line_${i + 1}`); }
  });
}

function withLock(lockPath, fn) {
  fs.mkdirSync(path.dirname(lockPath), { recursive: true, mode: 0o700 });
  let fd;
  try { fd = fs.openSync(lockPath, 'wx', 0o600); }
  catch (err) { if (err.code === 'EEXIST') throw new Error('ha_runtime_challenge_store_busy'); throw err; }
  try { return fn(); }
  finally {
    try { fs.closeSync(fd); } catch {}
    try { fs.unlinkSync(lockPath); } catch {}
  }
}

function appendDurable(filePath, record) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  if (fs.existsSync(filePath)) {
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('ha_runtime_challenge_store_file_invalid');
  }
  const fd = fs.openSync(filePath, 'a', 0o600);
  try { fs.writeSync(fd, JSON.stringify(record) + '\n'); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
}

class HARuntimeChallengeStore {
  constructor(filePath) {
    if (!filePath) throw new Error('ha_runtime_challenge_store_path_required');
    this.filePath = path.resolve(String(filePath));
    this.lockPath = `${this.filePath}.lock`;
  }

  verify() {
    const list = rows(this.filePath);
    let prior = null;
    const issued = new Map();
    const consumed = new Set();
    for (let i = 0; i < list.length; i += 1) {
      const row = list[i];
      if (!row || !['ISSUED', 'CONSUMED'].includes(row.event) || row.sequence !== i + 1) throw new Error('ha_runtime_challenge_record_invalid');
      if (row.previous_record_sha256 !== prior) throw new Error('ha_runtime_challenge_chain_broken');
      const supplied = hash64('ha_runtime_challenge_record_sha256', row.record_sha256);
      const copy = { ...row }; delete copy.record_sha256;
      if (sha256(canonicalJson(copy)) !== supplied) throw new Error('ha_runtime_challenge_record_hash_mismatch');
      const nonce = hash64('ha_runtime_challenge_nonce_sha256', row.nonce_sha256);
      if (row.event === 'ISSUED') {
        if (issued.has(nonce)) throw new Error('ha_runtime_challenge_duplicate_nonce');
        if (!Number.isFinite(Date.parse(row.issued_at)) || !Number.isFinite(Date.parse(row.expires_at)) || Date.parse(row.expires_at) <= Date.parse(row.issued_at)) throw new Error('ha_runtime_challenge_issue_time_invalid');
        issued.set(nonce, row);
      } else {
        if (!issued.has(nonce)) throw new Error('ha_runtime_challenge_consume_without_issue');
        if (consumed.has(nonce)) throw new Error('ha_runtime_challenge_duplicate_consume');
        if (!Number.isFinite(Date.parse(row.consumed_at))) throw new Error('ha_runtime_challenge_consumed_at_invalid');
        hash64('ha_runtime_challenge_observation_sha256', row.observation_sha256);
        consumed.add(nonce);
      }
      prior = supplied;
    }
    return Object.freeze({ verified: true, count: list.length, head_sha256: prior, issued_count: issued.size, consumed_count: consumed.size, rows: Object.freeze(list.map(r => Object.freeze({ ...r }))) });
  }

  issue({ ttl_ms = 30000, now = Date.now() } = {}) {
    const ttl = Number(ttl_ms);
    if (!Number.isSafeInteger(ttl) || ttl < 5000 || ttl > 60000) throw new Error('ha_runtime_challenge_ttl_invalid');
    if (!Number.isFinite(Number(now))) throw new Error('ha_runtime_challenge_now_invalid');
    return withLock(this.lockPath, () => {
      const proof = this.verify();
      const nonceSha256 = sha256(crypto.randomBytes(32));
      const body = {
        schema: 'g-bank-ha-runtime-challenge-event/v2', event: 'ISSUED', sequence: proof.count + 1,
        nonce_sha256: nonceSha256, issued_at: new Date(now).toISOString(), expires_at: new Date(Number(now) + ttl).toISOString(),
        previous_record_sha256: proof.head_sha256, grants_external_rights: false, permits_value_movement_by_itself: false,
      };
      const record = { ...body, record_sha256: sha256(canonicalJson(body)) };
      appendDurable(this.filePath, record);
      return Object.freeze({ nonce_sha256: nonceSha256, issued_at: body.issued_at, expires_at: body.expires_at, issue_record_sha256: record.record_sha256 });
    });
  }

  consume({ nonce_sha256, observation_sha256, now = Date.now() } = {}) {
    const nonce = hash64('ha_runtime_challenge_nonce_sha256', nonce_sha256);
    const observation = hash64('ha_runtime_challenge_observation_sha256', observation_sha256);
    if (!Number.isFinite(Number(now))) throw new Error('ha_runtime_challenge_now_invalid');
    return withLock(this.lockPath, () => {
      const proof = this.verify();
      const issue = proof.rows.find(row => row.event === 'ISSUED' && row.nonce_sha256 === nonce);
      if (!issue) throw new Error('ha_runtime_challenge_not_issued');
      if (proof.rows.some(row => row.event === 'CONSUMED' && row.nonce_sha256 === nonce)) throw new Error('ha_runtime_challenge_replay');
      if (Date.parse(issue.expires_at) <= Number(now)) throw new Error('ha_runtime_challenge_expired');
      const body = {
        schema: 'g-bank-ha-runtime-challenge-event/v2', event: 'CONSUMED', sequence: proof.count + 1,
        nonce_sha256: nonce, observation_sha256: observation, consumed_at: new Date(now).toISOString(),
        previous_record_sha256: proof.head_sha256, grants_external_rights: false, permits_value_movement_by_itself: false,
      };
      const record = { ...body, record_sha256: sha256(canonicalJson(body)) };
      appendDurable(this.filePath, record);
      return Object.freeze({ nonce_sha256: nonce, observation_sha256: observation, consumed_at: body.consumed_at, consume_record_sha256: record.record_sha256, challenge_store_head_sha256: record.record_sha256 });
    });
  }
}

module.exports = { HARuntimeChallengeStore, appendDurable };
