'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { InboundStore } = require('../g-bank-sovereign-v2/inbound-store');
const { verifyInboundStatement, reconcileInboundStatement } = require('../g-bank-sovereign-v2/inbound-statement-reconciliation');

const NOW = Date.parse('2026-09-10T21:00:00.000Z');
const DATE = '2026-09-10';

function statement(entries, overrides = {}) {
  const body = {
    schema: 'g-bank-inbound-settlement-statement/v2',
    source: 'VERIFIED_EXTERNAL_STATEMENT',
    business_date: DATE,
    currency: 'EUR',
    entries,
    observed_at: new Date(NOW - 1000).toISOString(),
    ...overrides,
  };
  return Object.freeze({ ...body, statement_sha256: sha256(canonicalJson(body)) });
}

function storeWithRows() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-inbound-recon-v2-'));
  const store = new InboundStore(path.join(root, 'inbound.jsonl'));
  const a = store.claim({
    inbound_id: 'IN-A', event_sha256: 'a'.repeat(64), target_account_id: 'G:CUSTOMER:A',
    amount_minor: 1000, currency: 'EUR', settlement_business_date: DATE, now: NOW - 5000,
  });
  store.transition({
    inbound_id: 'IN-A', expected_state: 'CLAIMED', to_state: 'PENDING', evidence_sha256: a.record.event_sha256,
    ledger_record_sha256: '1'.repeat(64), now: NOW - 4000,
  });
  const b = store.claim({
    inbound_id: 'IN-B', event_sha256: 'b'.repeat(64), target_account_id: 'G:CUSTOMER:B',
    amount_minor: 2500, currency: 'EUR', settlement_business_date: DATE, now: NOW - 3000,
  });
  store.transition({
    inbound_id: 'IN-B', expected_state: 'CLAIMED', to_state: 'PENDING', evidence_sha256: b.record.event_sha256,
    ledger_record_sha256: '2'.repeat(64), now: NOW - 2000,
  });
  store.transition({
    inbound_id: 'IN-B', expected_state: 'PENDING', to_state: 'AVAILABLE', evidence_sha256: '3'.repeat(64),
    ledger_record_sha256: '4'.repeat(64), now: NOW - 1000,
  });
  return store;
}

const cleanStatement = statement([
  { inbound_id: 'IN-A', amount_minor: 1000, currency: 'EUR', status: 'SETTLED', creditor_iban: 'NL91ABNA0417164300' },
  { inbound_id: 'IN-B', amount_minor: 2500, currency: 'EUR', status: 'SETTLED', creditor_iban: 'NL02ABNA0123456789' },
]);
assert.equal(verifyInboundStatement(cleanStatement, { now: NOW }).entries.length, 2);
const clean = reconcileInboundStatement({ inboundStore: storeWithRows(), statement: cleanStatement, now: NOW });
assert.equal(clean.state, 'PASS');
assert.equal(clean.internal_inbound_count, 2);
assert.equal(clean.external_inbound_count, 2);

const missingInternal = reconcileInboundStatement({
  inboundStore: storeWithRows(),
  statement: statement([
    { inbound_id: 'IN-A', amount_minor: 1000, currency: 'EUR', status: 'SETTLED' },
    { inbound_id: 'IN-B', amount_minor: 2500, currency: 'EUR', status: 'SETTLED' },
    { inbound_id: 'IN-C', amount_minor: 300, currency: 'EUR', status: 'SETTLED' },
  ]),
  now: NOW,
});
assert.equal(missingInternal.state, 'BLOCK');
assert(missingInternal.reasons.includes('EXTERNAL_INBOUND_MISSING_FROM_G_BANK'));

const missingExternal = reconcileInboundStatement({
  inboundStore: storeWithRows(),
  statement: statement([
    { inbound_id: 'IN-A', amount_minor: 1000, currency: 'EUR', status: 'SETTLED' },
  ]),
  now: NOW,
});
assert.equal(missingExternal.state, 'BLOCK');
assert(missingExternal.reasons.includes('G_BANK_INBOUND_MISSING_FROM_EXTERNAL_STATEMENT'));

const amountMismatch = reconcileInboundStatement({
  inboundStore: storeWithRows(),
  statement: statement([
    { inbound_id: 'IN-A', amount_minor: 1001, currency: 'EUR', status: 'SETTLED' },
    { inbound_id: 'IN-B', amount_minor: 2500, currency: 'EUR', status: 'SETTLED' },
  ]),
  now: NOW,
});
assert.equal(amountMismatch.state, 'BLOCK');
assert(amountMismatch.reasons.includes('INBOUND_AMOUNT_MISMATCH'));

const tampered = { ...cleanStatement, entries: [{ ...cleanStatement.entries[0], amount_minor: 9999 }, cleanStatement.entries[1]] };
assert.throws(() => verifyInboundStatement(tampered, { now: NOW }), /hash_mismatch/);
assert.throws(() => verifyInboundStatement(statement([
  { inbound_id: 'IN-A', amount_minor: 1000, currency: 'USD', status: 'SETTLED' },
]), { now: NOW }), /currency_mismatch/);
assert.throws(() => verifyInboundStatement(statement([
  { inbound_id: 'IN-A', amount_minor: 1000, currency: 'EUR', status: 'SETTLED' },
  { inbound_id: 'IN-A', amount_minor: 1000, currency: 'EUR', status: 'SETTLED' },
]), { now: NOW }), /duplicate_inbound_id/);

console.log('G-BANK sovereign v2 inbound settlement reconciliation tests: PASS');
