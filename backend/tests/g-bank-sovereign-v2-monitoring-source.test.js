'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { AccountRegistry } = require('../g-bank-sovereign-v2/accounts');
const { SovereignLedger } = require('../g-bank-sovereign-v2/ledger');
const { deriveCustomerActivityMetrics, assessCustomerActivityFromLedger } = require('../g-bank-sovereign-v2/transaction-activity-source');

const H = c => c.repeat(64);
const CUSTOMER = 'G:CUSTOMER-SUBJECT:MONSRC001';
const policy = {
  review_single_minor: 100000,
  suspend_single_minor: 500000,
  review_window_outbound_minor: 250000,
  suspend_window_outbound_minor: 1000000,
  review_transaction_count: 20,
  review_new_counterparty_count: 5,
  review_rapid_sequence_count: 5,
  suspend_rapid_sequence_count: 20,
  review_return_or_recall_count: 3,
};

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-monitor-source-v2-'));
const accounts = new AccountRegistry(path.join(root, 'accounts.json'));
const ledger = new SovereignLedger(path.join(root, 'ledger.jsonl'));
accounts.register({
  account_id: 'G:CUSTOMER:MONSRC', type: 'CUSTOMER', currency: 'EUR', iban: 'NL91ABNA0417164300', owner_binding_sha256: H('1'), metadata: { customer_id: CUSTOMER },
});
accounts.register({
  account_id: 'G:SETTLEMENT:MONSRC', type: 'SETTLEMENT', currency: 'EUR', owner_binding_sha256: H('2'),
});

const start = new Date(Date.now() - 60000).toISOString();
ledger.post({
  transaction_id: 'MONSRC-OUT-1',
  reference: 'OUT-1',
  entries: [
    { account_id: 'G:CUSTOMER:MONSRC', side: 'DEBIT', amount_minor: 120000, currency: 'EUR' },
    { account_id: 'G:SETTLEMENT:MONSRC', side: 'CREDIT', amount_minor: 120000, currency: 'EUR' },
  ],
  metadata: { kind: 'OUTBOUND_SETTLEMENT', beneficiary_binding_sha256: H('a') },
});
ledger.post({
  transaction_id: 'MONSRC-IN-1',
  reference: 'IN-1',
  entries: [
    { account_id: 'G:SETTLEMENT:MONSRC', side: 'DEBIT', amount_minor: 5000, currency: 'EUR' },
    { account_id: 'G:CUSTOMER:MONSRC', side: 'CREDIT', amount_minor: 5000, currency: 'EUR' },
  ],
  metadata: { kind: 'INBOUND_SETTLEMENT_AVAILABLE', debtor_binding_sha256: H('b') },
});
const end = new Date(Date.now() + 1000).toISOString();

const source = deriveCustomerActivityMetrics({
  customer_id: CUSTOMER,
  accounts,
  ledger,
  currency: 'EUR',
  window_start: start,
  window_end: end,
});
assert.equal(source.metrics.transaction_count, 2);
assert.equal(source.metrics.total_outbound_minor, 120000);
assert.equal(source.metrics.total_inbound_minor, 5000);
assert.equal(source.metrics.max_single_transaction_minor, 120000);
assert.equal(source.metrics.distinct_counterparty_count, 2);
assert.equal(source.metrics.new_counterparty_count, 2);
assert.equal(source.metrics.rapid_sequence_count, 1);
assert.match(source.source_root_sha256, /^[0-9a-f]{64}$/);
assert.match(source.derivation_sha256, /^[0-9a-f]{64}$/);

const result = assessCustomerActivityFromLedger({
  customer_id: CUSTOMER,
  accounts,
  ledger,
  currency: 'EUR',
  window_start: start,
  window_end: end,
  policy,
  now: Date.now() + 1000,
});
assert.equal(result.assessment.state, 'REVIEW_REQUIRED');
assert(result.assessment.reasons.includes('SINGLE_TRANSACTION_REVIEW_THRESHOLD'));
assert.equal(result.assessment.source_root_sha256, result.source.source_root_sha256);

const priorRoot = source.source_root_sha256;
ledger.post({
  transaction_id: 'MONSRC-OUT-2',
  reference: 'OUT-2',
  entries: [
    { account_id: 'G:CUSTOMER:MONSRC', side: 'DEBIT', amount_minor: 1000, currency: 'EUR' },
    { account_id: 'G:SETTLEMENT:MONSRC', side: 'CREDIT', amount_minor: 1000, currency: 'EUR' },
  ],
  metadata: { kind: 'OUTBOUND_SETTLEMENT', beneficiary_binding_sha256: H('c') },
});
const changed = deriveCustomerActivityMetrics({
  customer_id: CUSTOMER,
  accounts,
  ledger,
  currency: 'EUR',
  window_start: start,
  window_end: new Date(Date.now() + 1000).toISOString(),
});
assert.notEqual(changed.source_root_sha256, priorRoot, 'ledger head change must change monitoring source root');
assert.equal(changed.metrics.transaction_count, 3);

console.log('G-BANK sovereign v2 ledger-derived monitoring source tests: PASS');
