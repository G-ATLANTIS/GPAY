#!/usr/bin/env node
'use strict';

function evaluateRevolutManualRelease(input = {}) {
  const amount = Number(input.amount_in_minor);
  if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('amount_in_minor_invalid');
  if (String(input.currency || 'EUR').toUpperCase() !== 'EUR') throw new Error('currency_not_supported');
  const blockers = [];
  const checks = [
    ['current_account_verified', 'CURRENT_REVOLUT_ACCOUNT_EVIDENCE_REQUIRED'],
    ['funds_available_verified', 'AVAILABLE_FUNDS_VERIFICATION_REQUIRED'],
    ['funds_sufficient', 'AVAILABLE_FUNDS_INSUFFICIENT'],
    ['bank_limit_verified', 'BANK_LIMIT_VERIFICATION_REQUIRED'],
    ['amount_covered', 'BANK_LIMIT_INSUFFICIENT'],
    ['dealer_identity_verified', 'DEALER_IDENTITY_VERIFICATION_REQUIRED'],
    ['beneficiary_verified', 'BENEFICIARY_VERIFICATION_REQUIRED'],
    ['invoice_verified', 'INVOICE_VERIFICATION_REQUIRED'],
    ['vin_verified', 'VIN_VERIFICATION_REQUIRED'],
    ['payment_reference_verified', 'PAYMENT_REFERENCE_VERIFICATION_REQUIRED'],
    ['exact_amount_bound', 'EXACT_AMOUNT_BINDING_REQUIRED'],
    ['beneficiary_bound', 'BENEFICIARY_BINDING_REQUIRED'],
    ['sca_path_verified', 'SCA_PATH_VERIFICATION_REQUIRED'],
    ['fresh_owner_approval', 'FRESH_OWNER_APPROVAL_REQUIRED']
  ];
  for (const [field, code] of checks) if (input[field] !== true) blockers.push(code);
  return {
    schema: 'atlas-revolut-manual-release-v1',
    rail_id: 'revolut-manual-sca',
    amount_in_minor: amount,
    currency: 'EUR',
    state: blockers.length ? 'BLOCKED' : 'READY_FOR_MANUAL_APP_ENTRY',
    blockers,
    requires_user_revolut_app_approval: true,
    payment_splitting_to_evade_limits: 'DENY',
    payment_endpoint_call_permitted: false,
    network_payment_call_performed: false,
    provider_executed_equals_creditor_settled: false,
    value_moved: false
  };
}

function buildManualAppInstruction(input = {}) {
  const release = evaluateRevolutManualRelease(input);
  if (release.state !== 'READY_FOR_MANUAL_APP_ENTRY') throw new Error('revolut_manual_release_blocked');
  const iban = String(input.raw_beneficiary_iban || '').trim();
  const name = String(input.beneficiary_name || '').trim();
  const reference = String(input.payment_reference || '').trim();
  if (!iban || !name || !reference) throw new Error('manual_payment_fields_required');
  return {
    schema: 'atlas-revolut-manual-app-instruction-v1',
    rail_id: 'revolut-manual-sca',
    amount_in_minor: release.amount_in_minor,
    currency: 'EUR',
    beneficiary_name: name,
    beneficiary_iban: iban,
    payment_reference: reference,
    intent_binding_sha256: String(input.intent_binding_sha256 || ''),
    requires_user_revolut_app_approval: true,
    payment_endpoint_call_permitted: false,
    network_request_performed: false,
    value_moved: false
  };
}

if (require.main === module) {
  const result = evaluateRevolutManualRelease({amount_in_minor:29490000,currency:'EUR'});
  console.log(JSON.stringify(result, null, 2));
  if (result.state !== 'READY_FOR_MANUAL_APP_ENTRY') process.exitCode = 2;
}
module.exports = { evaluateRevolutManualRelease, buildManualAppInstruction };
