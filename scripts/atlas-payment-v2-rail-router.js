#!/usr/bin/env node
'use strict';

const { schemeForEur } = require('./atlas-payment-v2-policy');

function asMinor(value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error('amount_in_minor_invalid');
  return n;
}

function evaluateRail(input = {}) {
  const amount = asMinor(input.amount_in_minor);
  const currency = String(input.currency || '').toUpperCase();
  const scheme = currency === 'EUR' ? schemeForEur(amount) : null;
  const blockers = [];

  if (currency !== 'EUR') blockers.push('CURRENCY_NOT_SUPPORTED');
  if (input.provider_entitlement_verified !== true) blockers.push('PROVIDER_ENTITLEMENT_REQUIRED');
  if (input.provider_id_verified !== true) blockers.push('PROVIDER_ID_REQUIRED');
  if (input.beneficiary_verified !== true) blockers.push('BENEFICIARY_VERIFICATION_REQUIRED');
  if (input.bank_limit_verified !== true) blockers.push('BANK_LIMIT_VERIFICATION_REQUIRED');
  if (!Number.isSafeInteger(input.max_amount_in_minor) || input.max_amount_in_minor < amount) {
    blockers.push('AMOUNT_NOT_SUPPORTED');
  }
  if (scheme === 'SEPA_CREDIT') {
    if (input.provider_supports_sepa_credit !== true) {
      blockers.push('SEPA_CREDIT_NOT_VERIFIED');
    }
  } else if (scheme === 'INSTANT_PREFERRED') {
    if (input.provider_supports_instant !== true && input.provider_supports_sepa_credit !== true) {
      blockers.push('NO_SUPPORTED_EUR_SCHEME');
    }
  }

  const sca = input.new_sca_required;
  if (sca !== true && sca !== false) blockers.push('SCA_REQUIREMENT_UNKNOWN');

  const unique = Array.from(new Set(blockers)).sort();
  const eligible = unique.length === 0;
  let state = 'BLOCKED';
  if (eligible && sca === true) state = 'ELIGIBLE_REQUIRES_SCA';
  if (eligible && sca === false) state = 'ELIGIBLE_NO_NEW_SCA';

  return {
    version: 2,
    schema: 'atlas-payment-rail-router-v2',
    provider: 'truelayer',
    rail_id: scheme === 'SEPA_CREDIT' ? 'TRUELAYER_SEPA_CREDIT' : 'TRUELAYER_EUR',
    scheme_selection: scheme,
    amount_in_minor: amount,
    currency,
    state,
    execution_candidate: eligible,
    sca_required: sca === true,
    blockers: unique,
    payment_created: false,
    value_moved: false
  };
}

module.exports = { evaluateRail };
