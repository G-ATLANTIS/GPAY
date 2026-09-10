'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function createAccountBalanceView({ accounts, ledger, inboundStore, account_id, now = Date.now() }) {
  if (!accounts || typeof accounts.get !== 'function') throw new Error('account_registry_required');
  if (!ledger || typeof ledger.balance !== 'function' || typeof ledger.verify !== 'function') throw new Error('sovereign_ledger_required');
  if (!inboundStore || typeof inboundStore.currentAll !== 'function' || typeof inboundStore.verify !== 'function') throw new Error('inbound_store_required');
  const account = accounts.get(account_id);
  if (account.type !== 'CUSTOMER') throw new Error('customer_account_required');
  const ledgerProof = ledger.verify();
  const inboundProof = inboundStore.verify();
  const available = ledger.balance(account.account_id, account.currency);
  if (!Number.isSafeInteger(available)) throw new Error('available_balance_invalid');
  let pendingInbound = 0;
  for (const row of inboundStore.currentAll()) {
    if (row.target_account_id !== account.account_id || row.currency !== account.currency || row.state !== 'PENDING') continue;
    const amount = Number(row.amount_minor);
    if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('pending_inbound_amount_invalid');
    pendingInbound += amount;
    if (!Number.isSafeInteger(pendingInbound)) throw new Error('pending_inbound_balance_overflow');
  }
  const body = {
    schema: 'g-bank-account-balance-view/v2',
    account_id: account.account_id,
    currency: account.currency,
    account_status: account.status,
    available_balance_minor: available,
    pending_inbound_minor: pendingInbound,
    projected_balance_minor: available + pendingInbound,
    ledger_head_sha256: ledgerProof.head_sha256,
    inbound_state_head_sha256: inboundProof.head_sha256,
    observed_at: new Date(now).toISOString(),
  };
  if (!Number.isSafeInteger(body.projected_balance_minor)) throw new Error('projected_balance_overflow');
  return Object.freeze({ ...body, balance_view_sha256: sha256(canonicalJson(body)) });
}

module.exports = { createAccountBalanceView };
