'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { assertCurrency } = require('./ledger');

function nonNegative(name, value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${name}_invalid`);
  return n;
}

function hash64(name, value) {
  const v = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) throw new Error(`${name}_invalid`);
  return v;
}

function sumBalances(trial, accountIds) {
  let total = 0;
  for (const id of accountIds) {
    const value = Number(trial.balances[id] || 0);
    if (!Number.isSafeInteger(value)) throw new Error('treasury_balance_invalid');
    total += value;
    if (!Number.isSafeInteger(total)) throw new Error('treasury_balance_overflow');
  }
  return total;
}

function assessTreasuryPosition({
  accounts,
  ledger,
  currency = 'EUR',
  settlementLiquidityEvidence,
  minimum_prefunding_minor = 0,
  reserve_buffer_minor = 0,
  stressed_outflow_minor = 0,
  now = Date.now(),
}) {
  if (!accounts || typeof accounts.list !== 'function') throw new Error('account_registry_required');
  if (!ledger || typeof ledger.verify !== 'function' || typeof ledger.trialBalance !== 'function') throw new Error('sovereign_ledger_required');
  const ccy = assertCurrency(currency);
  const evidence = settlementLiquidityEvidence;
  if (!evidence || evidence.state !== 'VERIFIED') throw new Error('settlement_liquidity_evidence_required');
  if (String(evidence.currency || '').toUpperCase() !== ccy) throw new Error('settlement_liquidity_currency_mismatch');
  const available = nonNegative('settlement_available_minor', evidence.available_minor);
  const evidenceHash = hash64('settlement_liquidity_evidence_sha256', evidence.evidence_sha256);
  const observed = Date.parse(evidence.observed_at);
  if (!Number.isFinite(observed) || observed > now + 30000 || now - observed > 5 * 60 * 1000) throw new Error('settlement_liquidity_evidence_stale');

  const minimumPrefunding = nonNegative('minimum_prefunding_minor', minimum_prefunding_minor);
  const reserveBuffer = nonNegative('reserve_buffer_minor', reserve_buffer_minor);
  const stressedOutflow = nonNegative('stressed_outflow_minor', stressed_outflow_minor);

  const ledgerProof = ledger.verify();
  if (ledgerProof.verified !== true) throw new Error('ledger_not_verified');
  const trial = ledger.trialBalance(ccy);
  if (trial.balanced !== true || trial.total_minor !== 0) throw new Error('ledger_not_balanced');

  const active = accounts.list({ currency: ccy, status: 'ACTIVE' });
  const suspenseIds = active.filter(a => a.type === 'SUSPENSE').map(a => a.account_id);
  const settlementIds = active.filter(a => a.type === 'SETTLEMENT').map(a => a.account_id);
  if (!suspenseIds.length) throw new Error('suspense_account_missing');
  if (!settlementIds.length) throw new Error('settlement_account_missing');

  const pendingOutbound = Math.max(0, sumBalances(trial, suspenseIds));
  const internallyBookedSettlementOut = Math.max(0, sumBalances(trial, settlementIds));
  const required = pendingOutbound + minimumPrefunding + reserveBuffer + stressedOutflow;
  if (!Number.isSafeInteger(required)) throw new Error('treasury_requirement_overflow');
  const headroom = available - required;

  const body = {
    schema: 'g-bank-treasury-position/v2',
    state: headroom >= 0 ? 'PASS' : 'BLOCK',
    currency: ccy,
    settlement_available_minor: available,
    pending_outbound_holds_minor: pendingOutbound,
    internally_booked_settlement_out_minor: internallyBookedSettlementOut,
    minimum_prefunding_minor: minimumPrefunding,
    reserve_buffer_minor: reserveBuffer,
    stressed_outflow_minor: stressedOutflow,
    required_settlement_liquidity_minor: required,
    settlement_headroom_minor: headroom,
    settlement_liquidity_evidence_sha256: evidenceHash,
    ledger_head_sha256: ledgerProof.head_sha256,
    assessed_at: new Date(now).toISOString(),
  };
  return Object.freeze({ ...body, assessment_sha256: sha256(canonicalJson(body)) });
}

module.exports = { assessTreasuryPosition };
