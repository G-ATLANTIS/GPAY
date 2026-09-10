'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function parseTime(name, value) {
  const t = Date.parse(value);
  if (!Number.isFinite(t)) throw new Error(`${name}_invalid`);
  return t;
}

function createAccountStatement({ accounts, ledger, account_id, from, to, now = Date.now() }) {
  if (!accounts || typeof accounts.get !== 'function') throw new Error('account_registry_required');
  if (!ledger || typeof ledger.records !== 'function' || typeof ledger.verify !== 'function') throw new Error('sovereign_ledger_required');
  const account = accounts.get(account_id);
  if (account.type !== 'CUSTOMER') throw new Error('customer_account_required');
  const fromMs = parseTime('statement_from', from);
  const toMs = parseTime('statement_to', to);
  if (toMs < fromMs) throw new Error('statement_range_invalid');
  if (toMs > now + 30000) throw new Error('statement_to_in_future');

  const ledgerProof = ledger.verify();
  let opening = 0;
  let closing = 0;
  const entries = [];
  for (const record of ledger.records()) {
    const recordTime = parseTime('ledger_observed_at', record.observed_at);
    for (const entry of record.entries || []) {
      if (entry.account_id !== account.account_id || entry.currency !== account.currency) continue;
      const delta = entry.side === 'CREDIT' ? entry.amount_minor : -entry.amount_minor;
      if (!Number.isSafeInteger(delta)) throw new Error('statement_delta_invalid');
      if (recordTime < fromMs) opening += delta;
      if (recordTime <= toMs) closing += delta;
      if (recordTime >= fromMs && recordTime <= toMs) {
        entries.push(Object.freeze({
          sequence: record.sequence,
          transaction_id: record.transaction_id,
          reference: record.reference,
          observed_at: record.observed_at,
          side: entry.side,
          amount_minor: entry.amount_minor,
          delta_minor: delta,
          running_balance_minor: null,
          record_sha256: record.record_sha256,
        }));
      }
      if (!Number.isSafeInteger(opening) || !Number.isSafeInteger(closing)) throw new Error('statement_balance_overflow');
    }
  }

  let running = opening;
  const normalizedEntries = entries.map(item => {
    running += item.delta_minor;
    if (!Number.isSafeInteger(running)) throw new Error('statement_running_balance_overflow');
    return Object.freeze({ ...item, running_balance_minor: running });
  });
  if (running !== closing) throw new Error('statement_closing_balance_mismatch');

  const body = {
    schema: 'g-bank-account-statement/v2',
    account_id: account.account_id,
    iban: account.iban,
    currency: account.currency,
    account_status: account.status,
    from: new Date(fromMs).toISOString(),
    to: new Date(toMs).toISOString(),
    opening_balance_minor: opening,
    closing_balance_minor: closing,
    entry_count: normalizedEntries.length,
    entries: normalizedEntries,
    ledger_record_count: ledgerProof.record_count,
    ledger_head_sha256: ledgerProof.head_sha256,
    generated_at: new Date(now).toISOString(),
  };
  return Object.freeze({ ...body, statement_sha256: sha256(canonicalJson(body)) });
}

module.exports = { createAccountStatement };
