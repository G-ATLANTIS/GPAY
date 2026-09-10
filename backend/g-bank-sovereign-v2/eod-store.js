'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');

class EndOfDayStore {
  constructor(rootDir) {
    this.rootDir = path.resolve(rootDir);
    fs.mkdirSync(this.rootDir, { recursive: true, mode: 0o700 });
  }

  _file(businessDate) {
    const date = String(businessDate || '');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error('business_date_invalid');
    return path.join(this.rootDir, `${date}.json`);
  }

  read(businessDate) {
    try {
      const value = JSON.parse(fs.readFileSync(this._file(businessDate), 'utf8'));
      return Object.freeze(value);
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  verify(close) {
    if (!close || close.schema !== 'g-bank-end-of-day-close/v2') throw new Error('eod_close_invalid');
    if (!/^[0-9a-f]{64}$/i.test(String(close.close_sha256 || ''))) throw new Error('eod_close_hash_invalid');
    const { close_sha256, ...body } = close;
    if (sha256(canonicalJson(body)) !== close_sha256) throw new Error('eod_close_hash_mismatch');
    return true;
  }

  commit(close) {
    this.verify(close);
    if (close.state !== 'CLOSED') throw new Error('eod_close_not_closed');
    const file = this._file(close.business_date);
    const lock = `${file}.lock`;
    let fd;
    try {
      fd = fs.openSync(lock, 'wx', 0o600);
    } catch (err) {
      if (err.code === 'EEXIST') throw new Error('eod_store_busy');
      throw err;
    }
    try {
      if (fs.existsSync(file)) {
        const existing = JSON.parse(fs.readFileSync(file, 'utf8'));
        this.verify(existing);
        if (existing.close_sha256 === close.close_sha256) return Object.freeze(existing);
        throw new Error('business_date_already_closed_with_different_root');
      }
      const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
      const payload = JSON.stringify(close, null, 2) + '\n';
      fs.writeFileSync(tmp, payload, { flag: 'wx', mode: 0o600 });
      const tmpFd = fs.openSync(tmp, 'r');
      try { fs.fsyncSync(tmpFd); } finally { fs.closeSync(tmpFd); }
      fs.renameSync(tmp, file);
      const dirFd = fs.openSync(this.rootDir, 'r');
      try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
      return Object.freeze({ ...close });
    } finally {
      try { fs.closeSync(fd); } catch {}
      try { fs.unlinkSync(lock); } catch {}
    }
  }
}

module.exports = { EndOfDayStore };
