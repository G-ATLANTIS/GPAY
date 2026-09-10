'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');

class ReceiptLedger {
  constructor(filePath) {
    this.filePath = path.resolve(filePath);
    this.lockPath = `${this.filePath}.lock`;
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
  }

  readAll() {
    try {
      return fs.readFileSync(this.filePath, 'utf8')
        .split('\n')
        .filter(Boolean)
        .map(line => JSON.parse(line));
    } catch (err) {
      if (err.code === 'ENOENT') return [];
      throw err;
    }
  }

  verify() {
    const rows = this.readAll();
    let prev = 'GENESIS';
    for (let i = 0; i < rows.length; i += 1) {
      const row = rows[i];
      if (row.sequence !== i + 1) throw new Error('receipt_sequence_invalid');
      if (row.previous_record_sha256 !== prev) throw new Error('receipt_chain_broken');
      const { record_sha256, ...body } = row;
      const expected = sha256(canonicalJson(body));
      if (expected !== record_sha256) throw new Error('receipt_hash_invalid');
      prev = record_sha256;
    }
    return { valid: true, count: rows.length, head_sha256: prev };
  }

  append(event) {
    let lock;
    try {
      lock = fs.openSync(this.lockPath, 'wx', 0o600);
      const rows = this.readAll();
      if (rows.length) this.verify();
      const previous = rows.length ? rows[rows.length - 1].record_sha256 : 'GENESIS';
      const body = {
        schema: 'g-bank-live-receipt/v1',
        sequence: rows.length + 1,
        previous_record_sha256: previous,
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
    } finally {
      if (lock !== undefined) fs.closeSync(lock);
      try { fs.unlinkSync(this.lockPath); } catch (err) { if (err.code !== 'ENOENT') throw err; }
    }
  }
}

module.exports = { ReceiptLedger };
