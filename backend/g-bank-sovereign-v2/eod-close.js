'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function verifyHashed(name, value, hashField) {
  if (!value || typeof value !== 'object') throw new Error(`${name}_required`);
  const supplied = String(value[hashField] || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) throw new Error(`${name}_hash_invalid`);
  const { [hashField]: omitted, ...body } = value;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error(`${name}_hash_mismatch`);
  return value;
}

function createEndOfDayClose({
  business_date,
  checkpoint,
  invariantAudit,
  safeguardingAssessment,
  liquidityAssessment,
  treasuryAssessment,
  resilienceAssessment,
  settlementReconciliation,
  now = Date.now(),
}) {
  const date = String(business_date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error('business_date_invalid');
  if (!checkpoint || checkpoint.schema !== 'g-bank-sovereign-state-checkpoint/v2' || !/^[0-9a-f]{64}$/i.test(String(checkpoint.state_root_sha256 || ''))) {
    throw new Error('checkpoint_invalid');
  }

  const invariant = verifyHashed('invariant_audit', invariantAudit, 'audit_sha256');
  const safeguarding = verifyHashed('safeguarding', safeguardingAssessment, 'assessment_sha256');
  const liquidity = verifyHashed('liquidity', liquidityAssessment, 'assessment_sha256');
  const treasury = verifyHashed('treasury', treasuryAssessment, 'assessment_sha256');
  const resilience = verifyHashed('resilience', resilienceAssessment, 'assessment_sha256');
  const reconciliation = verifyHashed('settlement_reconciliation', settlementReconciliation, 'reconciliation_sha256');
  if (reconciliation.schema !== 'g-bank-settlement-reconciliation/v2') throw new Error('settlement_reconciliation_schema_invalid');
  if (reconciliation.business_date !== date) throw new Error('settlement_reconciliation_business_date_mismatch');

  const reasons = [];
  if (invariant.state !== 'PASS') reasons.push('INVARIANT_AUDIT_BLOCKED');
  if (safeguarding.state !== 'PASS') reasons.push('SAFEGUARDING_BLOCKED');
  if (liquidity.state !== 'PASS') reasons.push('LIQUIDITY_BLOCKED');
  if (treasury.state !== 'PASS') reasons.push('TREASURY_BLOCKED');
  if (resilience.state !== 'PASS') reasons.push('RESILIENCE_BLOCKED');
  if (reconciliation.state !== 'PASS') reasons.push('SETTLEMENT_RECONCILIATION_BLOCKED');

  const checkpointTime = Date.parse(checkpoint.checkpointed_at);
  if (!Number.isFinite(checkpointTime)) reasons.push('CHECKPOINT_TIME_INVALID');
  else if (new Date(checkpointTime).toISOString().slice(0, 10) !== date) reasons.push('CHECKPOINT_BUSINESS_DATE_MISMATCH');

  const body = {
    schema: 'g-bank-end-of-day-close/v2',
    state: reasons.length ? 'BLOCK' : 'CLOSED',
    business_date: date,
    reasons,
    state_root_sha256: checkpoint.state_root_sha256,
    invariant_audit_sha256: invariant.audit_sha256,
    safeguarding_assessment_sha256: safeguarding.assessment_sha256,
    liquidity_assessment_sha256: liquidity.assessment_sha256,
    treasury_assessment_sha256: treasury.assessment_sha256,
    resilience_assessment_sha256: resilience.assessment_sha256,
    settlement_reconciliation_sha256: reconciliation.reconciliation_sha256,
    settlement_statement_sha256: reconciliation.statement_sha256,
    closed_at: new Date(now).toISOString(),
  };
  return Object.freeze({ ...body, close_sha256: sha256(canonicalJson(body)) });
}

module.exports = { createEndOfDayClose, verifyHashed };
