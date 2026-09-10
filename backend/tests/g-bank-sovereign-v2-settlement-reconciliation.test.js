'use strict';

const assert = require('node:assert/strict');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { verifyStatement, reconcileSettlementStatement } = require('../g-bank-sovereign-v2/settlement-statement-reconciliation');

const NOW = Date.parse('2026-09-10T21:00:00.000Z');

function statement(entries) {
  const body = {
    schema: 'g-bank-settlement-statement/v2',
    source: 'VERIFIED_EXTERNAL_STATEMENT',
    business_date: '2026-09-10',
    currency: 'EUR',
    settlement_system: 'AUTHORIZED-TEST-BOUNDARY',
    entries,
    observed_at: new Date(NOW - 1000).toISOString(),
  };
  return Object.freeze({ ...body, statement_sha256: sha256(canonicalJson(body)) });
}

const receipts = [
  {
    event: 'SOVEREIGN_SETTLEMENT_VERIFIED',
    submission_id: 'SUB-001',
    amount_minor: 1000,
    currency: 'EUR',
    observed_at: '2026-09-10T10:00:00.000Z',
    value_moved: true,
  },
  {
    event: 'SOVEREIGN_SETTLEMENT_VERIFIED',
    submission_id: 'SUB-002',
    amount_minor: 2500,
    currency: 'EUR',
    observed_at: '2026-09-10T11:00:00.000Z',
    value_moved: true,
  },
  {
    event: 'SOVEREIGN_SETTLEMENT_PENDING',
    submission_id: 'SUB-PENDING',
    amount_minor: 900,
    currency: 'EUR',
    observed_at: '2026-09-10T12:00:00.000Z',
    value_moved: false,
  },
];

const cleanStatement = statement([
  { submission_id: 'SUB-001', amount_minor: 1000, currency: 'EUR', status: 'SETTLED', settlement_reference: 'EXT-1' },
  { submission_id: 'SUB-002', amount_minor: 2500, currency: 'EUR', status: 'SETTLED', settlement_reference: 'EXT-2' },
]);

assert.equal(verifyStatement(cleanStatement, { now: NOW }).entries.length, 2);
const clean = reconcileSettlementStatement({ receiptRows: receipts, statement: cleanStatement, now: NOW });
assert.equal(clean.state, 'PASS');
assert.equal(clean.internal_settlement_count, 2);
assert.equal(clean.external_settlement_count, 2);

const amountMismatch = reconcileSettlementStatement({
  receiptRows: receipts,
  statement: statement([
    { submission_id: 'SUB-001', amount_minor: 1000, currency: 'EUR', status: 'SETTLED' },
    { submission_id: 'SUB-002', amount_minor: 2600, currency: 'EUR', status: 'SETTLED' },
  ]),
  now: NOW,
});
assert.equal(amountMismatch.state, 'BLOCK');
assert(amountMismatch.reasons.includes('SETTLEMENT_AMOUNT_MISMATCH'));

const missingAndUnexpected = reconcileSettlementStatement({
  receiptRows: receipts,
  statement: statement([
    { submission_id: 'SUB-001', amount_minor: 1000, currency: 'EUR', status: 'SETTLED' },
    { submission_id: 'SUB-999', amount_minor: 777, currency: 'EUR', status: 'SETTLED' },
  ]),
  now: NOW,
});
assert.equal(missingAndUnexpected.state, 'BLOCK');
assert(missingAndUnexpected.reasons.includes('INTERNAL_SETTLEMENT_MISSING_FROM_EXTERNAL_STATEMENT'));
assert(missingAndUnexpected.reasons.includes('UNEXPECTED_EXTERNAL_SETTLEMENT'));

const duplicateInternal = reconcileSettlementStatement({
  receiptRows: [...receipts, { ...receipts[0] }],
  statement: cleanStatement,
  now: NOW,
});
assert.equal(duplicateInternal.state, 'BLOCK');
assert(duplicateInternal.reasons.includes('DUPLICATE_INTERNAL_SETTLEMENT_RECEIPT'));

const tampered = { ...cleanStatement, entries: [{ ...cleanStatement.entries[0], amount_minor: 9999 }, cleanStatement.entries[1]] };
assert.throws(() => verifyStatement(tampered, { now: NOW }), /hash_mismatch/);

assert.throws(() => verifyStatement(statement([
  { submission_id: 'SUB-001', amount_minor: 1000, currency: 'EUR', status: 'PENDING' },
]), { now: NOW }), /non_settled_entry/);

console.log('G-BANK sovereign v2 settlement reconciliation tests: PASS');
