'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');
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

function requireEvidenceHash(value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error('account_status_evidence_sha256_invalid');
  return hash;
}

class AccountRegistry {
  constructor(filePath) {
    this.filePath = path.resolve(filePath);
    this.lockPath = `${this.filePath}.lock`;
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
  }

  _load() {
    if (!fs.existsSync(this.filePath)) return { schema: 'g-bank-account-registry/v2', accounts: [], registry_sha256: null };
    const doc = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
    if (doc.schema !== 'g-bank-account-registry/v2' || !Array.isArray(doc.accounts)) throw new Error('account_registry_schema_invalid');
    const supplied = doc.registry_sha256;
    const copy = { ...doc, registry_sha256: null };
    const expected = sha256(canonicalJson(copy));
    if (supplied !== expected) throw new Error('account_registry_hash_mismatch');
    return doc;
  }

  _save(doc) {
    const next = { ...doc, registry_sha256: null };
    next.registry_sha256 = sha256(canonicalJson(next));
    const tmp = `${this.filePath}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(next, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    fs.renameSync(tmp, this.filePath);
    return next;
  }

  _withLock(fn) {
    let lockFd;
    try {
      lockFd = fs.openSync(this.lockPath, 'wx', 0o600);
    } catch (err) {
      if (err.code === 'EEXIST') throw new Error('account_registry_busy');
      throw err;
    }
    try {
      return fn();
    } finally {
      try { fs.closeSync(lockFd); } catch {}
      try { fs.unlinkSync(this.lockPath); } catch {}
    }
  }

  register({ account_id, type, currency = 'EUR', iban = null, owner_binding_sha256, metadata = {} }) {
    const id = assertAccountId(account_id);
    const ccy = assertCurrency(currency);
    const kind = String(type || '').toUpperCase();
    if (!['CUSTOMER', 'TREASURY', 'SETTLEMENT', 'SUSPENSE', 'FEES', 'SAFEGUARDING'].includes(kind)) throw new Error('account_type_invalid');
    const ownerHash = String(owner_binding_sha256 || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(ownerHash)) throw new Error('owner_binding_sha256_invalid');
    const normalizedIban = iban ? normalizeIban(iban) : null;
    if (normalizedIban && !isValidIban(normalizedIban)) throw new Error('iban_invalid');

    return this._withLock(() => {
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
        status_sequence: 1,
        status_evidence_sha256: null,
        metadata,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });
      return Object.freeze({ ...this._save(doc).accounts.find(a => a.account_id === id) });
    });
  }

  transitionStatus({ account_id, expected_status, to_status, evidence_sha256, reason = null, now = Date.now() }) {
    const id = assertAccountId(account_id);
    const expected = String(expected_status || '').toUpperCase();
    const next = String(to_status || '').toUpperCase();
    const allowed = {
      ACTIVE: new Set(['SUSPENDED']),
      SUSPENDED: new Set(['ACTIVE', 'CLOSED']),
      CLOSED: new Set(),
    };
    if (!allowed[expected] || !allowed[expected].has(next)) throw new Error('account_status_transition_invalid');
    const evidence = requireEvidenceHash(evidence_sha256);

    return this._withLock(() => {
      const doc = this._load();
      const index = doc.accounts.findIndex(a => a.account_id === id);
      if (index < 0) throw new Error('account_not_found');
      const account = doc.accounts[index];
      if (account.status !== expected) throw new Error('account_status_conflict');
      const updated = {
        ...account,
        status: next,
        status_sequence: Number(account.status_sequence || 1) + 1,
        status_evidence_sha256: evidence,
        status_reason: reason ? String(reason).slice(0, 256) : null,
        updated_at: new Date(now).toISOString(),
      };
      doc.accounts[index] = updated;
      const saved = this._save(doc);
      return Object.freeze({ ...saved.accounts[index] });
    });
  }

  list({ type = null, currency = null, status = null } = {}) {
    const kind = type ? String(type).toUpperCase() : null;
    const ccy = currency ? assertCurrency(currency) : null;
    const st = status ? String(status).toUpperCase() : null;
    return Object.freeze(this._load().accounts
      .filter(account => !kind || account.type === kind)
      .filter(account => !ccy || account.currency === ccy)
      .filter(account => !st || account.status === st)
      .map(account => Object.freeze({ ...account })));
  }

  get(accountId) {
    const id = assertAccountId(accountId);
    const account = this._load().accounts.find(a => a.account_id === id);
    if (!account) throw new Error('account_not_found');
    return Object.freeze({ ...account });
  }

  findByIban(iban) {
    const normalized = normalizeIban(iban);
    if (!isValidIban(normalized)) throw new Error('iban_invalid');
    const account = this._load().accounts.find(a => a.iban === normalized);
    if (!account) throw new Error('account_not_found_for_iban');
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
