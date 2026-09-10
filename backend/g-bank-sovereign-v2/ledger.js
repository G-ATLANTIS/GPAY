'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('./canonical');

function assertAccountId(value) {
  const id = String(value || '');
  if (!/^[A-Z0-9:_-]{3,128}$/.test(id)) throw new Error('ledger_account_id_invalid');
  return id;
}

function assertCurrency(value) {
  const currency = String(value || '').toUpperCase();
  if (!/^[A-Z]{3}$/.test(currency)) throw new Error('ledger_currency_invalid');
  return currency;
}

function assertMinor(value) {
  const amount = Number(value);
  if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('ledger_amount_minor_invalid');
  return amount;
}

class SovereignLedger {
  constructor(filePath) {
    this.filePath = path.resolve(filePath);
    this.lockPath = `${this.filePath}.lock`;
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
  }

  _records() {
    if (!fs.existsSync(this.filePath)) return [];
    const text = fs.readFileSync(this.filePath, 'utf8').trim();
    if (!text) return [];
    return text.split('\n').map((line, index) => {
      try { return JSON.parse(line); }
      catch { throw new Error(`ledger_corrupt_line_${index + 1}`); }
    });
  }

  verify() {
    const records = this._records();
    let prev = 'GENESIS';
    for (let i = 0; i < records.length; i += 1) {
      const record = records[i];
      if (record.sequence !== i + 1) throw new Error('ledger_sequence_invalid');
      if (record.previous_record_sha256 !== prev) throw new Error('ledger_hash_chain_broken');
      const supplied = record.record_sha256;
      const copy = { ...record };
      delete copy.record_sha256;
      const expected = sha256(canonicalJson(copy));
      if (supplied !== expected) throw new Error('ledger_record_hash_mismatch');
      prev = supplied;
    }
    return Object.freeze({ verified: true, record_count: records.length, head_sha256: prev });
  }

  balance(accountId, currency) {
    const account = assertAccountId(accountId);
    const ccy = assertCurrency(currency);
    let balance = 0;
    for (const record of this._records()) {
      for (const entry of record.entries || []) {
        if (entry.account_id !== account || entry.currency !== ccy) continue;
        balance += entry.side === 'CREDIT' ? entry.amount_minor : -entry.amount_minor;
      }
    }
    return balance;
  }

  post({ transaction_id = crypto.randomUUID(), reference, entries, metadata = {} }) {
    if (!Array.isArray(entries) || entries.length < 2) throw new Error('ledger_entries_invalid');
    const normalized = entries.map(entry => ({
      account_id: assertAccountId(entry.account_id),
      side: entry.side === 'DEBIT' ? 'DEBIT' : entry.side === 'CREDIT' ? 'CREDIT' : (() => { throw new Error('ledger_side_invalid'); })(),
      amount_minor: assertMinor(entry.amount_minor),
      currency: assertCurrency(entry.currency),
    }));

    const currencies = new Set(normalized.map(e => e.currency));
    if (currencies.size !== 1) throw new Error('ledger_multi_currency_transaction_forbidden');
    const debits = normalized.filter(e => e.side === 'DEBIT').reduce((s, e) => s + e.amount_minor, 0);
    const credits = normalized.filter(e => e.side === 'CREDIT').reduce((s, e) => s + e.amount_minor, 0);
    if (debits !== credits) throw new Error('ledger_not_balanced');

    let lockFd;
    try {
      lockFd = fs.openSync(this.lockPath, 'wx', 0o600);
    } catch (err) {
      if (err.code === 'EEXIST') throw new Error('ledger_busy');
      throw err;
    }

    try {
      const verification = this.verify();
      const records = this._records();
      if (records.some(r => r.transaction_id === transaction_id)) throw new Error('ledger_transaction_id_reused');

      const record = {
        schema: 'g-bank-sovereign-ledger-record/v2',
        sequence: records.length + 1,
        transaction_id: String(transaction_id),
        reference: String(reference || transaction_id),
        entries: normalized,
        metadata,
        observed_at: new Date().toISOString(),
        previous_record_sha256: verification.head_sha256,
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
    } finally {
      try { fs.closeSync(lockFd); } catch {}
      try { fs.unlinkSync(this.lockPath); } catch {}
    }
  }
}

module.exports = { SovereignLedger, assertAccountId, assertCurrency, assertMinor };
