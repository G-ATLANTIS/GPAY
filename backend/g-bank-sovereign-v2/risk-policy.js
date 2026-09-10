'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function int(name, value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < min || n > max) throw new Error(`${name}_invalid`);
  return n;
}

function normalizePolicy(input = {}) {
  const policy = {
    schema: 'g-bank-sovereign-risk-policy/v2',
    currency: String(input.currency || 'EUR').toUpperCase(),
    max_single_amount_minor: int('max_single_amount_minor', input.max_single_amount_minor ?? 100000, { min: 1 }),
    max_daily_amount_minor: int('max_daily_amount_minor', input.max_daily_amount_minor ?? 500000, { min: 1 }),
    high_value_threshold_minor: int('high_value_threshold_minor', input.high_value_threshold_minor ?? 50000, { min: 1 }),
    high_value_quorum: int('high_value_quorum', input.high_value_quorum ?? 2, { min: 1, max: 16 }),
    normal_quorum: int('normal_quorum', input.normal_quorum ?? 1, { min: 1, max: 16 }),
    allowed_schemes: [...new Set((input.allowed_schemes || ['SCT', 'SCT_INST']).map(v => String(v).toUpperCase()))].sort(),
    blocked_beneficiary_hashes: [...new Set((input.blocked_beneficiary_hashes || []).map(v => String(v).toLowerCase()))].sort(),
    policy_epoch: int('policy_epoch', input.policy_epoch ?? 1, { min: 1 }),
  };
  if (!/^[A-Z]{3}$/.test(policy.currency)) throw new Error('policy_currency_invalid');
  for (const h of policy.blocked_beneficiary_hashes) {
    if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('blocked_beneficiary_hash_invalid');
  }
  if (!policy.allowed_schemes.length || policy.allowed_schemes.some(s => !['SCT', 'SCT_INST'].includes(s))) {
    throw new Error('allowed_schemes_invalid');
  }
  policy.policy_sha256 = sha256(canonicalJson(policy));
  return Object.freeze(policy);
}

function utcDay(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) throw new Error('receipt_observed_at_invalid');
  return new Date(t).toISOString().slice(0, 10);
}

function settledToday(receiptRows, { accountId, currency, now = Date.now() }) {
  const day = new Date(now).toISOString().slice(0, 10);
  let total = 0;
  for (const row of receiptRows || []) {
    if (row.event !== 'SOVEREIGN_SETTLEMENT_VERIFIED' || row.value_moved !== true) continue;
    if (row.source_account_id !== accountId || row.currency !== currency) continue;
    if (utcDay(row.observed_at) !== day) continue;
    const amount = Number(row.amount_minor);
    if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('settlement_receipt_amount_invalid');
    total += amount;
    if (!Number.isSafeInteger(total)) throw new Error('daily_velocity_overflow');
  }
  return total;
}

function evaluatePaymentPolicy({ prepared, policy, receiptRows = [], now = Date.now() }) {
  if (!prepared?.instruction) throw new Error('prepared_payment_required');
  const p = normalizePolicy(policy);
  const i = prepared.instruction;
  const reasons = [];
  if (i.currency !== p.currency) reasons.push('currency_not_allowed');
  if (!p.allowed_schemes.includes(i.scheme)) reasons.push('scheme_not_allowed');
  if (i.amount_minor > p.max_single_amount_minor) reasons.push('single_amount_limit_exceeded');
  if (p.blocked_beneficiary_hashes.includes(i.beneficiary_binding_sha256)) reasons.push('beneficiary_blocked');
  const daySettled = settledToday(receiptRows, { accountId: i.source_account_id, currency: i.currency, now });
  if (daySettled + i.amount_minor > p.max_daily_amount_minor) reasons.push('daily_amount_limit_exceeded');
  const requiredQuorum = i.amount_minor >= p.high_value_threshold_minor ? p.high_value_quorum : p.normal_quorum;
  const result = {
    schema: 'g-bank-sovereign-risk-decision/v2',
    decision: reasons.length ? 'DENY' : 'ALLOW',
    reasons,
    policy_sha256: p.policy_sha256,
    policy_epoch: p.policy_epoch,
    source_account_id: i.source_account_id,
    instruction_sha256: i.instruction_sha256,
    beneficiary_binding_sha256: i.beneficiary_binding_sha256,
    amount_minor: i.amount_minor,
    currency: i.currency,
    settled_today_minor: daySettled,
    projected_daily_minor: daySettled + i.amount_minor,
    required_quorum: requiredQuorum,
    evaluated_at: new Date(now).toISOString(),
  };
  result.decision_sha256 = sha256(canonicalJson(result));
  return Object.freeze(result);
}

module.exports = { normalizePolicy, evaluatePaymentPolicy, settledToday };
