#!/usr/bin/env node
'use strict';

const HIGH_VALUE_EUR_MINOR = 10_000_000; // EUR 100,000

function requirePositiveMinor(value) {
  const amount = Number(value);
  if (!Number.isSafeInteger(amount) || amount <= 0) {
    throw new Error('amount_in_minor_invalid');
  }
  return amount;
}

function schemeForEur(amountInMinor) {
  const amount = requirePositiveMinor(amountInMinor);
  return amount >= HIGH_VALUE_EUR_MINOR
    ? 'USER_SELECTED_SEPA'
    : 'INSTANT_PREFERRED';
}

function evaluatePreExecution(input = {}) {
  const amount = requirePositiveMinor(input.amount_in_minor);
  const currency = String(input.currency || '').toUpperCase();
  const blockers = [];

  if (currency !== 'EUR') blockers.push('CURRENCY_NOT_SUPPORTED');
  if (input.owner_approved !== true) blockers.push('OWNER_APPROVAL_REQUIRED');  if (input.provider_entitlement_verified !== true) {
    blockers.push('PROVIDER_ENTITLEMENT_REQUIRED');
  }
  if (input.beneficiary_verified !== true) {
    blockers.push('BENEFICIARY_VERIFICATION_REQUIRED');
  }
  if (input.bank_limit_verified !== true) {
    blockers.push('BANK_LIMIT_VERIFICATION_REQUIRED');
  } else if (!Number.isSafeInteger(input.bank_limit_minor) || input.bank_limit_minor < amount) {
    blockers.push('BANK_LIMIT_INSUFFICIENT');
  }
  if (input.signing_ready !== true) blockers.push('PROVIDER_SIGNING_NOT_READY');
  if (input.idempotency_bound !== true) blockers.push('IDEMPOTENCY_NOT_BOUND');
  if (input.sca_capable !== true) blockers.push('SCA_PATH_NOT_READY');
  if (input.live_gate_enabled !== true) blockers.push('LIVE_GATE_DISABLED');

  const highValue = currency === 'EUR' && amount >= HIGH_VALUE_EUR_MINOR;
  if (highValue && input.scheme_selection_capable !== true) {
    blockers.push('HIGH_VALUE_SCHEME_SELECTION_REQUIRED');
  }

  const scheme = currency === 'EUR' ? schemeForEur(amount) : null;
  const unique = Array.from(new Set(blockers)).sort();

  return {
    version: 2,
    schema: 'atlas-payment-pre-execution-v2',
    provider: 'truelayer',
    state: unique.length === 0 ? 'READY_TO_CREATE_PAYMENT' : 'BLOCKED',
    amount_in_minor: amount,
    currency,
    scheme_selection: scheme,
    sca_required: true,    blockers: unique,
    payment_endpoint_called: false,
    payment_created: false,
    value_moved: false
  };
}

module.exports = {
  HIGH_VALUE_EUR_MINOR,
  schemeForEur,
  evaluatePreExecution
};
