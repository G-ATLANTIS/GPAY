'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { assertCurrency, assertMinor } = require('./ledger');

function verifyInboundStatement(statement, { now = Date.now(), max_age_ms = 24 * 60 * 60 * 1000 } = {}) {
  if (!statement || statement.schema !== 'g-bank-inbound-settlement-statement/v2') throw new Error('inbound_statement_required');
  if (statement.source !== 'VERIFIED_EXTERNAL_STATEMENT') throw new Error('inbound_statement_source_invalid');
  const currency = assertCurrency(statement.currency);
  const businessDate = String(statement.business_date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(businessDate)) throw new Error('inbound_statement_business_date_invalid');
  const observed = Date.parse(statement.observed_at);
  if (!Number.isFinite(observed) || observed > now + 30000 || now - observed > max_age_ms) throw new Error('inbound_statement_stale');
  if (!Array.isArray(statement.entries)) throw new Error('inbound_statement_entries_invalid');
  const supplied = String(statement.statement_sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) throw new Error('inbound_statement_hash_invalid');
  const { statement_sha256, ...body } = statement;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('inbound_statement_hash_mismatch');

  const seen = new Set();
  const entries = statement.entries.map((entry, index) => {
    const inboundId = String(entry.inbound_id || '').trim();
    if (!inboundId || inboundId.length > 256) throw new Error(`inbound_statement_id_invalid_${index}`);
    if (seen.has(inboundId)) throw new Error('inbound_statement_duplicate_inbound_id');
    seen.add(inboundId);
    if (String(entry.status || '').toUpperCase() !== 'SETTLED') throw new Error('inbound_statement_non_settled_entry');
    const entryCurrency = assertCurrency(entry.currency || currency);
    if (entryCurrency !== currency) throw new Error('inbound_statement_currency_mismatch');
    return Object.freeze({
      inbound_id: inboundId,
      amount_minor: assertMinor(entry.amount_minor),
      currency: entryCurrency,
      creditor_iban: entry.creditor_iban ? String(entry.creditor_iban).replace(/\s+/g, '').toUpperCase() : null,
      settlement_reference: entry.settlement_reference ? String(entry.settlement_reference).slice(0, 256) : null,
    });
  });
  return Object.freeze({ business_date: businessDate, currency, entries, statement_sha256: supplied });
}

function reconcileInboundStatement({ inboundStore, statement, now = Date.now() }) {
  if (!inboundStore || typeof inboundStore.currentAll !== 'function' || typeof inboundStore.verify !== 'function') throw new Error('inbound_store_required');
  const verifiedStatement = verifyInboundStatement(statement, { now });
  const storeProof = inboundStore.verify();
  const internalRows = inboundStore.currentAll().filter(row =>
    row.settlement_business_date === verifiedStatement.business_date && row.currency === verifiedStatement.currency
  );
  const internal = new Map(internalRows.map(row => [row.inbound_id, row]));
  const external = new Map(verifiedStatement.entries.map(entry => [entry.inbound_id, entry]));
  const missingInternal = [];
  const missingExternal = [];
  const amountMismatches = [];
  const nonFinalizedInternal = [];

  for (const [id, entry] of external) {
    const row = internal.get(id);
    if (!row) {
      missingInternal.push(id);
      continue;
    }
    if (row.amount_minor !== entry.amount_minor) {
      amountMismatches.push({ inbound_id: id, internal_amount_minor: row.amount_minor, external_amount_minor: entry.amount_minor });
    }
    if (!['PENDING', 'AVAILABLE'].includes(row.state)) nonFinalizedInternal.push({ inbound_id: id, state: row.state });
  }
  for (const id of internal.keys()) {
    if (!external.has(id)) missingExternal.push(id);
  }

  missingInternal.sort();
  missingExternal.sort();
  amountMismatches.sort((a, b) => a.inbound_id.localeCompare(b.inbound_id));
  nonFinalizedInternal.sort((a, b) => a.inbound_id.localeCompare(b.inbound_id));
  const reasons = [];
  if (missingInternal.length) reasons.push('EXTERNAL_INBOUND_MISSING_FROM_G_BANK');
  if (missingExternal.length) reasons.push('G_BANK_INBOUND_MISSING_FROM_EXTERNAL_STATEMENT');
  if (amountMismatches.length) reasons.push('INBOUND_AMOUNT_MISMATCH');
  if (nonFinalizedInternal.length) reasons.push('INBOUND_NOT_POSTED_TO_PENDING_OR_AVAILABLE');

  const body = {
    schema: 'g-bank-inbound-settlement-reconciliation/v2',
    state: reasons.length ? 'BLOCK' : 'PASS',
    business_date: verifiedStatement.business_date,
    currency: verifiedStatement.currency,
    statement_sha256: verifiedStatement.statement_sha256,
    inbound_state_head_sha256: storeProof.head_sha256,
    internal_inbound_count: internal.size,
    external_inbound_count: external.size,
    missing_internal_inbound_ids: missingInternal,
    missing_external_inbound_ids: missingExternal,
    amount_mismatches: amountMismatches,
    non_finalized_internal: nonFinalizedInternal,
    reasons,
    reconciled_at: new Date(now).toISOString(),
  };
  return Object.freeze({ ...body, reconciliation_sha256: sha256(canonicalJson(body)) });
}

module.exports = { verifyInboundStatement, reconcileInboundStatement };
