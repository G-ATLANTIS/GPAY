#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { verifyCreditorSettlement } = require('../../scripts/atlas-payment-v2-creditor-settlement');

const h = value => crypto.createHash('sha256').update(value).digest('hex');
const paymentId = '0afd1f6a-f611-48ce-9488-321129bb3a70';

const receipt = verifyCreditorSettlement({
  payment_id: paymentId,
  amount_in_minor: 29_490_000,
  currency: 'EUR',
  beneficiary_binding_sha256: h('dealer-iban'),
  provider_execution_receipt_sha256: h('provider-executed'),
  external_evidence_sha256: h('creditor-proof'),
  source: 'CREDITOR_BANK_CONFIRMATION',
  independently_verified: true,
  confirmed_at: '2026-09-17T12:00:00Z'
});

assert.equal(receipt.creditor_confirmation_verified, true);
assert.equal(receipt.value_moved, true);
assert.throws(() => verifyCreditorSettlement({
  payment_id: paymentId,
  amount_in_minor: 29_490_000,
  currency: 'EUR',
  beneficiary_binding_sha256: h('dealer-iban'),
  provider_execution_receipt_sha256: h('provider-executed'),
  external_evidence_sha256: h('creditor-proof'),
  source: 'CREDITOR_SIGNED_RECEIPT',
  independently_verified: false,
  confirmed_at: '2026-09-17T12:00:00Z'
}), /settlement_not_independently_verified/);

assert.throws(() => verifyCreditorSettlement({
  payment_id: paymentId,
  amount_in_minor: 29_490_000,
  currency: 'EUR',
  beneficiary_binding_sha256: h('dealer-iban'),
  provider_execution_receipt_sha256: h('provider-executed'),
  external_evidence_sha256: h('creditor-proof'),
  source: 'UNKNOWN',
  independently_verified: true,
  confirmed_at: '2026-09-17T12:00:00Z'
}), /settlement_source_not_allowed/);

console.log('atlas-payment-v2-creditor-settlement: PASS');
