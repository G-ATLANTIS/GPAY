#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');

const STATES = Object.freeze([
  'INTENT_CAPTURED',
  'OWNER_APPROVED',
  'PROVIDER_ENTITLEMENT_VERIFIED',
  'BENEFICIARY_VERIFIED',
  'BANK_AND_AMOUNT_ELIGIBLE',
  'PAYMENT_CREATED_AWAITING_SCA',
  'USER_SCA_AUTHORIZED',
  'PROVIDER_EXECUTED',
  'CREDITOR_SETTLEMENT_CONFIRMED',
  'RECONCILED',
  'BLOCKED',
  'FAILED',
  'UNKNOWN'
]);

const ORDER = STATES.slice(0, 10);

function isHash(value) {
  return /^[0-9a-f]{64}$/i.test(String(value || ''));
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value ?? '')).digest('hex');
}
function assertState(value) {
  if (!STATES.includes(value)) throw new Error('state_invalid');
  return value;
}

function initialState({ intent_id, amount_in_minor, currency = 'EUR' }) {
  const amount = Number(amount_in_minor);
  if (!String(intent_id || '').trim()) throw new Error('intent_id_required');
  if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('amount_invalid');
  if (String(currency).toUpperCase() !== 'EUR') throw new Error('currency_invalid');
  const record = {
    version: 2,
    schema: 'atlas-payment-state-v2',
    intent_id: String(intent_id),
    amount_in_minor: amount,
    currency: 'EUR',
    state: 'INTENT_CAPTURED',
    payment_id: null,
    value_moved: false,
    creditor_settlement_confirmed: false,
    reconciled: false,
    evidence: {}
  };
  record.state_sha256 = sha256(JSON.stringify(record));
  return record;
}

function requireEvidence(evidence, field) {
  if (!isHash(evidence?.[field])) throw new Error(`${field}_required`);
}
function assertNext(current, target) {
  assertState(current);
  assertState(target);
  if (['BLOCKED', 'FAILED', 'UNKNOWN'].includes(target)) return;
  const index = ORDER.indexOf(current);
  if (index < 0 || ORDER[index + 1] !== target) {
    throw new Error(`invalid_transition_${current}_to_${target}`);
  }
}

function transition(record, target, evidence = {}) {
  if (!record || record.schema !== 'atlas-payment-state-v2') throw new Error('record_invalid');
  assertNext(record.state, target);

  const checks = {
    OWNER_APPROVED: 'owner_approval_sha256',
    PROVIDER_ENTITLEMENT_VERIFIED: 'provider_entitlement_sha256',
    BENEFICIARY_VERIFIED: 'beneficiary_verification_sha256',
    BANK_AND_AMOUNT_ELIGIBLE: 'bank_eligibility_sha256',
    PAYMENT_CREATED_AWAITING_SCA: 'provider_create_receipt_sha256',
    USER_SCA_AUTHORIZED: 'sca_authorization_sha256',
    PROVIDER_EXECUTED: 'provider_execution_receipt_sha256',
    CREDITOR_SETTLEMENT_CONFIRMED: 'creditor_settlement_receipt_sha256',
    RECONCILED: 'reconciliation_receipt_sha256'
  };

  if (checks[target]) requireEvidence(evidence, checks[target]);
  if (target === 'PAYMENT_CREATED_AWAITING_SCA' && !String(evidence.payment_id || '').trim()) {
    throw new Error('payment_id_required');
  }
  if (target === 'CREDITOR_SETTLEMENT_CONFIRMED') {
    if (evidence.creditor_confirmation_verified !== true) {
      throw new Error('creditor_confirmation_not_verified');
    }
    if (evidence.amount_in_minor !== record.amount_in_minor) {
      throw new Error('creditor_settlement_amount_mismatch');
    }
    if (String(evidence.currency).toUpperCase() !== record.currency) {
      throw new Error('creditor_settlement_currency_mismatch');
    }
  }

  const next = {
    ...record,
    state: target,
    payment_id: evidence.payment_id || record.payment_id,
    value_moved:
      target === 'CREDITOR_SETTLEMENT_CONFIRMED' || target === 'RECONCILED'
        ? true
        : record.value_moved,
    creditor_settlement_confirmed:
      target === 'CREDITOR_SETTLEMENT_CONFIRMED' || target === 'RECONCILED'
        ? true
        : record.creditor_settlement_confirmed,
    reconciled: target === 'RECONCILED',
    evidence: { ...record.evidence, ...evidence }
  };

  const unsigned = { ...next };
  delete unsigned.state_sha256;
  next.state_sha256 = sha256(JSON.stringify(unsigned));
  return next;
}

module.exports = { STATES, ORDER, initialState, transition };
