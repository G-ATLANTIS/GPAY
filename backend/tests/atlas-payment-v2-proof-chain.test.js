#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  verifyCreateResponse,
  verifyStatusResource
} = require('../../scripts/atlas-payment-v2-provider-evidence');
const {
  verifyCreditorSettlement
} = require('../../scripts/atlas-payment-v2-creditor-settlement');
const {
  verifySettlementProofChain
} = require('../../scripts/atlas-payment-v2-proof-chain');

const h = value => crypto.createHash('sha256').update(value).digest('hex');
const paymentId = '0afd1f6a-f611-48ce-9488-321129bb3a70';
const amount = 29_490_000;

const create = verifyCreateResponse({
  response: { id: paymentId, status: 'authorization_required' },
  expected_amount_in_minor: amount,
  expected_currency: 'EUR'
});
const status = verifyStatusResource({
  resource: {
    id: paymentId,
    status: 'executed',
    amount_in_minor: amount,
    currency: 'EUR'
  },
  expected_payment_id: paymentId,
  expected_amount_in_minor: amount,
  expected_currency: 'EUR'
});

const creditor = verifyCreditorSettlement({
  payment_id: paymentId,
  amount_in_minor: amount,
  currency: 'EUR',
  beneficiary_binding_sha256: h('dealer-iban'),
  provider_execution_receipt_sha256: status.receipt_sha256,
  external_evidence_sha256: h('creditor-proof'),
  source: 'CREDITOR_BANK_CONFIRMATION',
  independently_verified: true,
  confirmed_at: '2026-09-17T12:00:00Z'
});
const chain = verifySettlementProofChain({
  amount_in_minor: amount,
  currency: 'EUR',
  create_receipt: create,
  status_receipt: status,
  creditor_settlement_receipt: creditor
});
assert.equal(chain.settlement_proof_ready, true);
assert.equal(chain.value_moved, true);
assert.equal(chain.reconciled, false);

const tampered = { ...creditor, amount_in_minor: amount - 1 };
assert.throws(() => verifySettlementProofChain({
  amount_in_minor: amount,
  currency: 'EUR',
  create_receipt: create,
  status_receipt: status,
  creditor_settlement_receipt: tampered
}), /receipt_integrity_mismatch/);

console.log('atlas-payment-v2-proof-chain: PASS');
