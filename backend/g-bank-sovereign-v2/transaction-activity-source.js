'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { assessTransactionActivity } = require('./transaction-monitoring');

function counterpartyBinding(metadata = {}) {
  for (const field of ['counterparty_binding_sha256', 'beneficiary_binding_sha256', 'debtor_binding_sha256']) {
    const value = String(metadata?.[field] || '').toLowerCase();
    if (/^[0-9a-f]{64}$/.test(value)) return value;
  }
  return null;
}

function deriveCustomerActivityMetrics({
  customer_id,
  accounts,
  ledger,
  currency = 'EUR',
  window_start,
  window_end,
  rapid_interval_ms = 60 * 1000,
}) {
  const customerId = String(customer_id || '').trim();
  if (!customerId) throw new Error('activity_source_customer_id_invalid');
  if (!accounts || typeof accounts.list !== 'function') throw new Error('activity_source_accounts_required');
  if (!ledger || typeof ledger.records !== 'function' || typeof ledger.verify !== 'function') throw new Error('activity_source_ledger_required');
  const ccy = String(currency || '').toUpperCase();
  if (!/^[A-Z]{3}$/.test(ccy)) throw new Error('activity_source_currency_invalid');
  const start = Date.parse(window_start);
  const end = Date.parse(window_end);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) throw new Error('activity_source_window_invalid');
  const rapidMs = Number(rapid_interval_ms);
  if (!Number.isSafeInteger(rapidMs) || rapidMs < 1000) throw new Error('activity_source_rapid_interval_invalid');

  const verification = ledger.verify();
  if (verification.verified !== true) throw new Error('activity_source_ledger_not_verified');
  const linked = accounts.list({ type: 'CUSTOMER' })
    .filter(account => account.metadata?.customer_id === customerId && account.currency === ccy)
    .map(account => account.account_id)
    .sort();
  if (!linked.length) throw new Error('activity_source_no_linked_accounts');
  const accountSet = new Set(linked);

  let transactionCount = 0;
  let totalInbound = 0;
  let totalOutbound = 0;
  let maxSingle = 0;
  let returnRecallCount = 0;
  const inWindowCounterparties = new Set();
  const historicalCounterparties = new Set();
  const eventTimes = [];

  for (const record of ledger.records()) {
    const observed = Date.parse(record.observed_at);
    if (!Number.isFinite(observed)) throw new Error('activity_source_ledger_timestamp_invalid');
    const linkedEntries = (record.entries || []).filter(entry => accountSet.has(entry.account_id) && entry.currency === ccy);
    if (!linkedEntries.length) continue;
    const cp = counterpartyBinding(record.metadata);
    if (observed < start) {
      if (cp) historicalCounterparties.add(cp);
      continue;
    }
    if (observed > end) continue;

    transactionCount += 1;
    eventTimes.push(observed);
    if (cp) inWindowCounterparties.add(cp);
    if (/RETURN|RECALL/.test(String(record.metadata?.kind || '').toUpperCase())) returnRecallCount += 1;

    for (const entry of linkedEntries) {
      if (!Number.isSafeInteger(entry.amount_minor) || entry.amount_minor <= 0) throw new Error('activity_source_ledger_amount_invalid');
      maxSingle = Math.max(maxSingle, entry.amount_minor);
      if (entry.side === 'CREDIT') totalInbound += entry.amount_minor;
      else if (entry.side === 'DEBIT') totalOutbound += entry.amount_minor;
      else throw new Error('activity_source_ledger_side_invalid');
      if (!Number.isSafeInteger(totalInbound) || !Number.isSafeInteger(totalOutbound)) throw new Error('activity_source_amount_overflow');
    }
  }

  eventTimes.sort((a, b) => a - b);
  let rapidSequenceCount = 0;
  for (let i = 1; i < eventTimes.length; i += 1) {
    if (eventTimes[i] - eventTimes[i - 1] <= rapidMs) rapidSequenceCount += 1;
  }
  const newCounterparties = [...inWindowCounterparties].filter(value => !historicalCounterparties.has(value));

  const sourceBody = {
    schema: 'g-bank-transaction-activity-source/v2',
    customer_id: customerId,
    currency: ccy,
    account_ids: linked,
    window_start: new Date(start).toISOString(),
    window_end: new Date(end).toISOString(),
    ledger_head_sha256: verification.head_sha256,
    ledger_record_count: verification.record_count,
    rapid_interval_ms: rapidMs,
  };
  const sourceRoot = sha256(canonicalJson(sourceBody));
  const metrics = Object.freeze({
    transaction_count: transactionCount,
    total_inbound_minor: totalInbound,
    total_outbound_minor: totalOutbound,
    max_single_transaction_minor: maxSingle,
    distinct_counterparty_count: inWindowCounterparties.size,
    new_counterparty_count: newCounterparties.length,
    rapid_sequence_count: rapidSequenceCount,
    return_or_recall_count: returnRecallCount,
  });
  const body = {
    ...sourceBody,
    metrics,
    source_root_sha256: sourceRoot,
  };
  return Object.freeze({ ...body, derivation_sha256: sha256(canonicalJson(body)) });
}

function assessCustomerActivityFromLedger({ policy, now = Date.now(), ...sourceArgs }) {
  const source = deriveCustomerActivityMetrics(sourceArgs);
  return Object.freeze({
    source,
    assessment: assessTransactionActivity({
      customer_id: source.customer_id,
      currency: source.currency,
      window_start: source.window_start,
      window_end: source.window_end,
      ...source.metrics,
      source_root_sha256: source.source_root_sha256,
      policy,
      now,
    }),
  });
}

module.exports = { deriveCustomerActivityMetrics, assessCustomerActivityFromLedger };
