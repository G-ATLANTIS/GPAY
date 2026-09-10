'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { assertCurrency } = require('./ledger');

function validAssessment(name, value, schema) {
  if (!value || value.schema !== schema || !['PASS', 'BLOCK'].includes(value.state)) throw new Error(`${name}_assessment_invalid`);
  if (!/^[0-9a-f]{64}$/i.test(String(value.assessment_sha256 || ''))) throw new Error(`${name}_assessment_hash_invalid`);
  const { assessment_sha256, ...body } = value;
  if (sha256(canonicalJson(body)) !== assessment_sha256) throw new Error(`${name}_assessment_hash_mismatch`);
  return value;
}

function auditSovereignInvariants({ accounts, ledger, currency = 'EUR', safeguardingAssessment, liquidityAssessment, now = Date.now() }) {
  if (!accounts || typeof accounts.list !== 'function') throw new Error('account_registry_required');
  if (!ledger || typeof ledger.verify !== 'function' || typeof ledger.trialBalance !== 'function') throw new Error('sovereign_ledger_required');
  const ccy = assertCurrency(currency);
  const safeguarding = validAssessment('safeguarding', safeguardingAssessment, 'g-bank-safeguarding-assessment/v2');
  const liquidity = validAssessment('liquidity', liquidityAssessment, 'g-bank-liquidity-assessment/v2');

  const ledgerProof = ledger.verify();
  const trial = ledger.trialBalance(ccy);
  const active = accounts.list({ currency: ccy, status: 'ACTIVE' });
  const customers = active.filter(a => a.type === 'CUSTOMER');
  const safeguardingAccounts = active.filter(a => a.type === 'SAFEGUARDING');
  const suspenseAccounts = active.filter(a => a.type === 'SUSPENSE');
  const settlementAccounts = active.filter(a => a.type === 'SETTLEMENT');
  const reasons = [];

  if (ledgerProof.verified !== true || trial.balanced !== true || trial.total_minor !== 0) reasons.push('LEDGER_NOT_BALANCED');
  if (!safeguardingAccounts.length) reasons.push('SAFEGUARDING_ACCOUNT_MISSING');
  if (!suspenseAccounts.length) reasons.push('SUSPENSE_ACCOUNT_MISSING');
  if (!settlementAccounts.length) reasons.push('SETTLEMENT_ACCOUNT_MISSING');

  const negativeCustomerAccounts = customers
    .filter(a => (trial.balances[a.account_id] || 0) < 0)
    .map(a => a.account_id)
    .sort();
  if (negativeCustomerAccounts.length) reasons.push('NEGATIVE_CUSTOMER_BALANCE');
  if (safeguarding.state !== 'PASS') reasons.push('SAFEGUARDING_COVERAGE_BLOCKED');
  if (liquidity.state !== 'PASS') reasons.push('LIQUIDITY_HEADROOM_BLOCKED');

  const body = {
    schema: 'g-bank-sovereign-invariant-audit/v2',
    state: reasons.length ? 'BLOCK' : 'PASS',
    currency: ccy,
    reasons,
    negative_customer_accounts: negativeCustomerAccounts,
    active_customer_count: customers.length,
    active_safeguarding_account_count: safeguardingAccounts.length,
    active_suspense_account_count: suspenseAccounts.length,
    active_settlement_account_count: settlementAccounts.length,
    ledger_record_count: ledgerProof.record_count,
    ledger_head_sha256: ledgerProof.head_sha256,
    trial_total_minor: trial.total_minor,
    safeguarding_assessment_sha256: safeguarding.assessment_sha256,
    liquidity_assessment_sha256: liquidity.assessment_sha256,
    audited_at: new Date(now).toISOString(),
  };
  return Object.freeze({ ...body, audit_sha256: sha256(canonicalJson(body)) });
}

module.exports = { auditSovereignInvariants };
