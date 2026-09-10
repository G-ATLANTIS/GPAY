'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { SovereignReceiptLedger } = require('../g-bank-sovereign-v2/receipt-ledger');
const { SovereignLedger } = require('../g-bank-sovereign-v2/ledger');
const { AccountRegistry } = require('../g-bank-sovereign-v2/accounts');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-v2-integrity-'));
const H = c => c.repeat(64);

// Canonical object ordering must be stable.
assert.equal(canonicalJson({ b: 2, a: 1 }), canonicalJson({ a: 1, b: 2 }));
assert.equal(sha256(canonicalJson({ b: 2, a: 1 })), sha256(canonicalJson({ a: 1, b: 2 })));

// Receipt chain must detect historical mutation.
const receiptsPath = path.join(root, 'receipts.jsonl');
const receipts = new SovereignReceiptLedger(receiptsPath);
receipts.append({ event: 'A', value_moved: false });
receipts.append({ event: 'B', value_moved: false });
assert.equal(receipts.verify().valid, true);
const receiptRows = fs.readFileSync(receiptsPath, 'utf8').trim().split('\n').map(JSON.parse);
receiptRows[0].event = 'TAMPERED';
fs.writeFileSync(receiptsPath, receiptRows.map(JSON.stringify).join('\n') + '\n');
assert.throws(() => receipts.verify(), /receipt_hash_invalid/);

// Value ledger must detect historical mutation and sequence faults.
const ledgerPath = path.join(root, 'ledger.jsonl');
const ledger = new SovereignLedger(ledgerPath);
ledger.post({
  transaction_id: 'INT-001',
  reference: 'integrity-test',
  entries: [
    { account_id: 'G:TREASURY:A', side: 'DEBIT', amount_minor: 500, currency: 'EUR' },
    { account_id: 'G:CUSTOMER:A', side: 'CREDIT', amount_minor: 500, currency: 'EUR' },
  ],
});
assert.equal(ledger.verify().verified, true);
const ledgerRows = fs.readFileSync(ledgerPath, 'utf8').trim().split('\n').map(JSON.parse);
ledgerRows[0].sequence = 99;
fs.writeFileSync(ledgerPath, ledgerRows.map(JSON.stringify).join('\n') + '\n');
assert.throws(() => ledger.verify(), /ledger_sequence_invalid/);

// Account registry is hash-bound and rejects mutation.
const accountsPath = path.join(root, 'accounts.json');
const accounts = new AccountRegistry(accountsPath);
accounts.register({
  account_id: 'G:CUSTOMER:001',
  type: 'CUSTOMER',
  currency: 'EUR',
  iban: 'NL91ABNA0417164300',
  owner_binding_sha256: H('a'),
});
assert.equal(accounts.get('G:CUSTOMER:001').currency, 'EUR');
const doc = JSON.parse(fs.readFileSync(accountsPath, 'utf8'));
doc.accounts[0].currency = 'USD';
fs.writeFileSync(accountsPath, JSON.stringify(doc, null, 2) + '\n');
assert.throws(() => accounts.get('G:CUSTOMER:001'), /account_registry_hash_mismatch/);

console.log('G-BANK sovereign v2 integrity tests: PASS');
