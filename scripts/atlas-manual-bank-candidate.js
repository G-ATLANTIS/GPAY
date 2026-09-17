#!/usr/bin/env node
'use strict';

function validUntil(value, now = new Date()) {
  const t = Date.parse(value || '');
  return Number.isFinite(t) && t > now.getTime();
}

function evaluateManualBankCandidate(input = {}, now = new Date()) {
  const target = Number(input.target_amount_in_minor || 0);
  if (!Number.isSafeInteger(target) || target <= 0) throw new Error('target_amount_in_minor_invalid');
  const blockers = [];
  const historical = input.historical_account_association_verified === true;
  const current = input.current_account_verified === true;
  const fundsVerified = input.available_funds_verified === true;
  const funds = Number(input.available_funds_in_minor || 0);
  const publicFresh = validUntil(input.public_constraint_expires_at, now);
  const standardMax = Number(input.public_standard_single_payment_max_in_minor || 0);
  const elevatedVerified = input.elevated_tier_verified === true;
  const elevatedMax = Number(input.elevated_single_payment_max_in_minor || 0);

  if (!historical) blockers.push('HISTORICAL_ACCOUNT_ASSOCIATION_REQUIRED');
  if (!current) blockers.push('CURRENT_ACCOUNT_EVIDENCE_REQUIRED');
  if (!fundsVerified) blockers.push('AVAILABLE_FUNDS_VERIFICATION_REQUIRED');
  if (!fundsVerified || funds < target) blockers.push('AVAILABLE_FUNDS_INSUFFICIENT');
  if (!publicFresh) blockers.push('PUBLIC_LIMIT_EVIDENCE_STALE_OR_MISSING');
  let effectiveMax = publicFresh ? standardMax : 0;
  let limitClass = 'STANDARD_RETAIL_PUBLIC_CONSTRAINT';
  if (elevatedVerified && elevatedMax > effectiveMax) {
    effectiveMax = elevatedMax;
    limitClass = 'ELEVATED_TIER_VERIFIED';
  }
  if (effectiveMax < target) blockers.push('SINGLE_PAYMENT_LIMIT_INSUFFICIENT');
  if (input.sca_path_verified !== true) blockers.push('SCA_PATH_VERIFICATION_REQUIRED');

  let state = 'BLOCKED';
  if (historical && !current) state = 'HISTORICAL_ACCOUNT_EVIDENCE_ONLY';
  if (publicFresh && effectiveMax < target) state = 'BLOCKED_PUBLIC_SINGLE_PAYMENT_LIMIT';
  if (blockers.length === 0) state = 'READY_FOR_MANUAL_BANK_ENTRY';

  return {
    schema: 'atlas-manual-bank-candidate-v1',
    bank_id: String(input.bank_id || ''),
    rail_id: String(input.rail_id || ''),
    target_amount_in_minor: target,
    state, blockers,
    limit_class: limitClass,
    effective_single_payment_max_in_minor: effectiveMax,
    public_constraint_source: String(input.public_constraint_source || ''),
    public_constraint_expires_at: String(input.public_constraint_expires_at || ''),
    payment_splitting_to_evade_limits: 'DENY',
    requires_user_bank_approval: true,
    payment_endpoint_call_permitted: false,
    network_payment_call_performed: false,
    value_moved: false
  };
}

if (require.main === module) {
  console.log(JSON.stringify(evaluateManualBankCandidate({
    bank_id:'example', rail_id:'example-manual-sca', target_amount_in_minor:29490000
  }), null, 2));
}

module.exports = { validUntil, evaluateManualBankCandidate };
