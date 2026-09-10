'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');

function assertAmount(value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error('velocity_amount_invalid');
  return n;
}

function assertLimit(value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error('velocity_limit_invalid');
  return n;
}

function dayFromNow(now) {
  const d = new Date(now);
  if (!Number.isFinite(d.getTime())) throw new Error('velocity_now_invalid');
  return d.toISOString().slice(0, 10);
}

class VelocityStore {
  constructor(rootDir) {
    this.rootDir = path.resolve(rootDir);
    fs.mkdirSync(this.rootDir, { recursive: true, mode: 0o700 });
  }

  _id(accountId, currency, day) {
    return sha256(`${accountId}\n${currency}\n${day}`);
  }

  _paths(accountId, currency, day) {
    const id = this._id(accountId, currency, day);
    return {
      file: path.join(this.rootDir, `${id}.json`),
      lock: path.join(this.rootDir, `${id}.lock`),
    };
  }

  _empty(accountId, currency, day) {
    return {
      schema: 'g-bank-sovereign-velocity-state/v2',
      account_id: String(accountId),
      currency: String(currency),
      day,
      reservations: [],
      state_sha256: null,
    };
  }

  _seal(doc) {
    const body = { ...doc, state_sha256: null };
    body.state_sha256 = sha256(canonicalJson(body));
    return body;
  }

  _readUnlocked(accountId, currency, day) {
    const { file } = this._paths(accountId, currency, day);
    if (!fs.existsSync(file)) return this._seal(this._empty(accountId, currency, day));
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
    const supplied = doc.state_sha256;
    const expected = this._seal({ ...doc, state_sha256: null }).state_sha256;
    if (supplied !== expected) throw new Error('velocity_state_hash_mismatch');
    if (doc.account_id !== String(accountId) || doc.currency !== String(currency) || doc.day !== day) {
      throw new Error('velocity_state_binding_mismatch');
    }
    return doc;
  }

  _writeUnlocked(file, doc) {
    const sealed = this._seal(doc);
    const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(sealed, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    const fd = fs.openSync(tmp, 'r');
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, file);
    return sealed;
  }

  _withLock(accountId, currency, day, fn) {
    const { file, lock } = this._paths(accountId, currency, day);
    let fd;
    try {
      fd = fs.openSync(lock, 'wx', 0o600);
    } catch (err) {
      if (err.code === 'EEXIST') throw new Error('velocity_state_busy');
      throw err;
    }
    try {
      const doc = this._readUnlocked(accountId, currency, day);
      return fn(doc, file);
    } finally {
      try { fs.closeSync(fd); } catch {}
      try { fs.unlinkSync(lock); } catch (err) { if (err.code !== 'ENOENT') throw err; }
    }
  }

  reserve({ idempotencyKey, accountId, currency, instructionSha256, amountMinor, maxDailyMinor, now = Date.now() }) {
    if (!idempotencyKey) throw new Error('velocity_idempotency_key_required');
    if (!/^[0-9a-f]{64}$/i.test(String(instructionSha256 || ''))) throw new Error('velocity_instruction_hash_invalid');
    const amount = assertAmount(amountMinor);
    const limit = assertLimit(maxDailyMinor);
    const day = dayFromNow(now);
    const keyHash = sha256(String(idempotencyKey));
    return this._withLock(accountId, currency, day, (doc, file) => {
      const existing = doc.reservations.find(r => r.key_sha256 === keyHash);
      if (existing) {
        if (existing.instruction_sha256 !== instructionSha256 || existing.amount_minor !== amount) {
          throw new Error('velocity_idempotency_reuse_mismatch');
        }
        return Object.freeze({ ...existing, idempotent_replay: true });
      }
      const committed = doc.reservations
        .filter(r => r.state === 'RESERVED' || r.state === 'SETTLED')
        .reduce((sum, r) => sum + r.amount_minor, 0);
      if (!Number.isSafeInteger(committed + amount)) throw new Error('velocity_total_overflow');
      if (committed + amount > limit) throw new Error('daily_amount_limit_exceeded_atomic');
      const record = {
        key_sha256: keyHash,
        instruction_sha256: instructionSha256,
        amount_minor: amount,
        state: 'RESERVED',
        reserved_at: new Date(now).toISOString(),
        updated_at: new Date(now).toISOString(),
      };
      doc.reservations.push(record);
      this._writeUnlocked(file, doc);
      return Object.freeze({ ...record, idempotent_replay: false });
    });
  }

  transition({ idempotencyKey, accountId, currency, to, now = Date.now() }) {
    if (!['SETTLED', 'RELEASED'].includes(to)) throw new Error('velocity_transition_invalid');
    const day = dayFromNow(now);
    const keyHash = sha256(String(idempotencyKey || ''));
    return this._withLock(accountId, currency, day, (doc, file) => {
      const record = doc.reservations.find(r => r.key_sha256 === keyHash);
      if (!record) throw new Error('velocity_reservation_missing');
      if (record.state === to) return Object.freeze({ ...record, idempotent_replay: true });
      if (record.state !== 'RESERVED') throw new Error(`velocity_transition_forbidden_${record.state}_to_${to}`);
      record.state = to;
      record.updated_at = new Date(now).toISOString();
      this._writeUnlocked(file, doc);
      return Object.freeze({ ...record, idempotent_replay: false });
    });
  }

  snapshot({ accountId, currency, now = Date.now() }) {
    const day = dayFromNow(now);
    const doc = this._readUnlocked(accountId, currency, day);
    const committed_minor = doc.reservations
      .filter(r => r.state === 'RESERVED' || r.state === 'SETTLED')
      .reduce((sum, r) => sum + r.amount_minor, 0);
    return Object.freeze({ day, committed_minor, reservation_count: doc.reservations.length, state_sha256: doc.state_sha256 });
  }
}

module.exports = { VelocityStore, dayFromNow };
