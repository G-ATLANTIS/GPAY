'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');

class SovereignReceiptLedger {
  constructor(filePath) {
    this.filePath = path.resolve(filePath);
    this.lockPath = `${this.filePath}.lock`;
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
  }

  readAll() {
    try {
      return fs.readFileSync(this.filePath, 'utf8').split('\n').filter(Boolean).map((line, i) => {
        try { return JSON.parse(line); }
        catch { throw new Error(`receipt_corrupt_line_${i + 1}`); }
      });
    } catch (err) {
      if (err.code === 'ENOENT') return [];
      throw err;
    }
  }

  verify() {
    const rows = this.readAll();
    let previous = 'GENESIS';
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      if (row.sequence !== i + 1) throw new Error('receipt_sequence_invalid');
      if (row.previous_record_sha256 !== previous) throw new Error('receipt_chain_broken');
      const { record_sha256, ...body } = row;
      if (record_sha256 !== sha256(canonicalJson(body))) throw new Error('receipt_hash_invalid');
      previous = record_sha256;
    }
    return Object.freeze({ valid: true, count: rows.length, head_sha256: previous });
  }

  append(event) {
    let lock;
    try {
      lock = fs.openSync(this.lockPath, 'wx', 0o600);
      const rows = this.readAll();
      const verified = this.verify();
      const body = {
        schema: 'g-bank-sovereign-receipt/v2',
        sequence: rows.length + 1,
        previous_record_sha256: verified.head_sha256,
        observed_at: new Date().toISOString(),
        ...event,
      };
      const row = { ...body, record_sha256: sha256(canonicalJson(body)) };
      const fd = fs.openSync(this.filePath, 'a', 0o600);
      try {
        fs.writeSync(fd, JSON.stringify(row) + '\n');
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      return Object.freeze(row);
    } catch (err) {
      if (err.code === 'EEXIST') throw new Error('receipt_ledger_busy');
      throw err;
    } finally {
      if (lock !== undefined) {
        try { fs.closeSync(lock); } catch {}
        try { fs.unlinkSync(this.lockPath); } catch (err) { if (err.code !== 'ENOENT') throw err; }
      }
    }
  }
}

module.exports = { SovereignReceiptLedger };
