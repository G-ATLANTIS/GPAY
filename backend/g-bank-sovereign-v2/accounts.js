'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-live-v1/canonical');
const { assertAccountId, assertCurrency } = require('./ledger');

function normalizeIban(value) {
  return String(value || '').replace(/\s+/g, '').toUpperCase();
}

function isValidIban(value) {
  const iban = normalizeIban(value);
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(iban)) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const digits = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of digits) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}

class AccountRegistry {
  constructor(filePath) {
    this.filePath = path.resolve(filePath);
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
  }

  _load() {
    if (!fs.existsSync(this.filePath)) return { schema: 'g-bank-account-registry/v2', accounts: [], registry_sha256: null };
    const doc = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
    const supplied = doc.registry_sha256;
    const copy = { ...doc, registry_sha256: null };
    const expected = sha256(canonicalJson(copy));
    if (supplied !== expected) throw new Error('account_registry_hash_mismatch');
    return doc;
  }

  _save(doc) {
    const next = { ...doc, registry_sha256: null };
    next.registry_sha256 = sha256(canonicalJson(next));
    const tmp = `${this.filePath}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(next, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    fs.renameSync(tmp, this.filePath);
    return next;
  }

  register({ account_id, type, currency = 'EUR', iban = null, owner_binding_sha256, metadata = {} }) {
    const id = assertAccountId(account_id);
    const ccy = assertCurrency(currency);
    const kind = String(type || '').toUpperCase();
    if (!['CUSTOMER', 'TREASURY', 'SETTLEMENT', 'SUSPENSE', 'FEES', 'SAFEGUARDING'].includes(kind)) {
      throw new Error('account_type_invalid');
    }
    const ownerHash = String(owner_binding_sha256 || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(ownerHash)) throw new Error('owner_binding_sha256_invalid');
    const normalizedIban = iban ? normalizeIban(iban) : null;
    if (normalizedIban && !isValidIban(normalizedIban)) throw new Error('iban_invalid');

    const doc = this._load();
    if (doc.accounts.some(a => a.account_id === id)) throw new Error('account_id_exists');
    if (normalizedIban && doc.accounts.some(a => a.iban === normalizedIban)) throw new Error('iban_already_bound');
    doc.accounts.push({
      schema: 'g-bank-account/v2',
      account_id: id,
      type: kind,
      currency: ccy,
      iban: normalizedIban,
      owner_binding_sha256: ownerHash,
      status: 'ACTIVE',
      metadata,
      created_at: new Date().toISOString(),
    });
    return this._save(doc).accounts.find(a => a.account_id === id);
  }

  get(accountId) {
    const id = assertAccountId(accountId);
    const account = this._load().accounts.find(a => a.account_id === id);
    if (!account) throw new Error('account_not_found');
    return Object.freeze({ ...account });
  }

  requireActive(accountId, currency) {
    const account = this.get(accountId);
    if (account.status !== 'ACTIVE') throw new Error('account_not_active');
    if (currency && account.currency !== assertCurrency(currency)) throw new Error('account_currency_mismatch');
    return account;
  }
}

module.exports = { AccountRegistry, normalizeIban, isValidIban };
