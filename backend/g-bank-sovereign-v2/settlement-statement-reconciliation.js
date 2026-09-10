'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { assertCurrency } = require('./ledger');

function positiveMinor(name, value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error(`${name}_invalid`);
  return n;
}

function verifyStatement(statement, { now = Date.now(), max_age_ms = 24 * 60 * 60 * 1000 } = {}) {
  if (!statement || statement.schema !== 'g-bank-settlement-statement/v2') throw new Error('settlement_statement_required');
  if (statement.source !== 'VERIFIED_EXTERNAL_STATEMENT') throw new Error('settlement_statement_source_invalid');
  const currency = assertCurrency(statement.currency);
  const date = String(statement.business_date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error('settlement_statement_business_date_invalid');
  const observed = Date.parse(statement.observed_at);
  if (!Number.isFinite(observed) || observed > now + 30000 || now - observed > max_age_ms) throw new Error('settlement_statement_stale');
  if (!Array.isArray(statement.entries)) throw new Error('settlement_statement_entries_invalid');
  const system = String(statement.settlement_system || '').trim();
  if (!system || system.length > 128) throw new Error('settlement_statement_system_invalid');
  const supplied = String(statement.statement_sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) throw new Error('settlement_statement_hash_invalid');
  const { statement_sha256, ...body } = statement;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('settlement_statement_hash_mismatch');

  const seen = new Set();
  const entries = statement.entries.map((entry, index) => {
    const submissionId = String(entry.submission_id || '').trim();
    if (!submissionId || submissionId.length > 256) throw new Error(`settlement_statement_submission_id_invalid_${index}`);
    if (seen.has(submissionId)) throw new Error('settlement_statement_duplicate_submission_id');
    seen.add(submissionId);
    const status = String(entry.status || '').toUpperCase();
    if (status !== 'SETTLED') throw new Error('settlement_statement_non_settled_entry');
    return Object.freeze({
      submission_id: submissionId,
      amount_minor: positiveMinor(`settlement_statement_amount_minor_${index}`, entry.amount_minor),
      currency: assertCurrency(entry.currency || currency),
      settlement_reference: entry.settlement_reference ? String(entry.settlement_reference).slice(0, 256) : null,
    });
  });
  return Object.freeze({ business_date: date, currency, settlement_system: system, entries, statement_sha256: supplied });
}

function reconcileSettlementStatement({ receiptRows, statement, now = Date.now() }) {
  if (!Array.isArray(receiptRows)) throw new Error('receipt_rows_required');
  const verified = verifyStatement(statement, { now });
  const internal = new Map();
  const duplicateInternal = [];

  for (const row of receiptRows) {
    if (row?.event !== 'SOVEREIGN_SETTLEMENT_VERIFIED' || row.value_moved !== true) continue;
    if (String(row.currency || '').toUpperCase() !== verified.currency) continue;
    const observed = Date.parse(row.observed_at);
    if (!Number.isFinite(observed) || new Date(observed).toISOString().slice(0, 10) !== verified.business_date) continue;
    const id = String(row.submission_id || '').trim();
    if (!id) continue;
    if (internal.has(id)) duplicateInternal.push(id);
    else internal.set(id, row);
  }

  const external = new Map(verified.entries.map(e => [e.submission_id, e]));
  const missingExternal = [];
  const unexpectedExternal = [];
  const amountMismatches = [];

  for (const [id, row] of internal) {
    const entry = external.get(id);
    if (!entry) {
      missingExternal.push(id);
      continue;
    }
    const amount = Number(row.amount_minor);
    if (!Number.isSafeInteger(amount) || amount <= 0 || amount !== entry.amount_minor) {
      amountMismatches.push({ submission_id: id, internal_amount_minor: amount, external_amount_minor: entry.amount_minor });
    }
  }
  for (const id of external.keys()) {
    if (!internal.has(id)) unexpectedExternal.push(id);
  }

  duplicateInternal.sort();
  missingExternal.sort();
  unexpectedExternal.sort();
  amountMismatches.sort((a, b) => a.submission_id.localeCompare(b.submission_id));
  const reasons = [];
  if (duplicateInternal.length) reasons.push('DUPLICATE_INTERNAL_SETTLEMENT_RECEIPT');
  if (missingExternal.length) reasons.push('INTERNAL_SETTLEMENT_MISSING_FROM_EXTERNAL_STATEMENT');
  if (unexpectedExternal.length) reasons.push('UNEXPECTED_EXTERNAL_SETTLEMENT');
  if (amountMismatches.length) reasons.push('SETTLEMENT_AMOUNT_MISMATCH');

  const body = {
    schema: 'g-bank-settlement-reconciliation/v2',
    state: reasons.length ? 'BLOCK' : 'PASS',
    business_date: verified.business_date,
    currency: verified.currency,
    settlement_system: verified.settlement_system,
    statement_sha256: verified.statement_sha256,
    internal_settlement_count: internal.size,
    external_settlement_count: external.size,
    duplicate_internal_submission_ids: duplicateInternal,
    missing_external_submission_ids: missingExternal,
    unexpected_external_submission_ids: unexpectedExternal,
    amount_mismatches: amountMismatches,
    reasons,
    reconciled_at: new Date(now).toISOString(),
  };
  return Object.freeze({ ...body, reconciliation_sha256: sha256(canonicalJson(body)) });
}

module.exports = { verifyStatement, reconcileSettlementStatement };
