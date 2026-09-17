#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');

function sha256(value) {
  return crypto.createHash('sha256').update(String(value ?? '')).digest('hex');
}

function verifyReceiptHash(receipt, field = 'receipt_sha256') {
  if (!receipt || typeof receipt !== 'object') throw new Error('receipt_invalid');
  const claimed = String(receipt[field] || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(claimed)) throw new Error('receipt_hash_invalid');
  const unsigned = { ...receipt };
  delete unsigned[field];
  const actual = sha256(JSON.stringify(unsigned));
  if (actual !== claimed) throw new Error('receipt_integrity_mismatch');
  return claimed;
}

function assertSame(value, expected, code) {
  if (value !== expected) throw new Error(code);
}

function verifySettlementProofChain(input = {}) {
  const amount = Number(input.amount_in_minor);
  const currency = String(input.currency || '').toUpperCase();
  if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('amount_invalid');
  if (currency !== 'EUR') throw new Error('currency_invalid');
  const created = input.create_receipt;
  const status = input.status_receipt;
  const creditor = input.creditor_settlement_receipt;

  const createHash = verifyReceiptHash(created);
  const statusHash = verifyReceiptHash(status);
  const creditorHash = verifyReceiptHash(creditor);

  assertSame(created.schema, 'atlas-payment-create-receipt-v2', 'create_schema_invalid');
  assertSame(status.schema, 'atlas-payment-status-receipt-v2', 'status_schema_invalid');
  assertSame(
    creditor.schema,
    'atlas-payment-creditor-settlement-receipt-v2',
    'creditor_schema_invalid'
  );

  assertSame(created.payment_id, status.payment_id, 'payment_id_chain_mismatch');
  assertSame(status.payment_id, creditor.payment_id, 'creditor_payment_id_mismatch');
  assertSame(created.amount_in_minor, amount, 'create_amount_mismatch');
  assertSame(status.amount_in_minor, amount, 'status_amount_mismatch');
  assertSame(creditor.amount_in_minor, amount, 'creditor_amount_mismatch');
  assertSame(created.currency, currency, 'create_currency_mismatch');
  assertSame(status.currency, currency, 'status_currency_mismatch');
  assertSame(creditor.currency, currency, 'creditor_currency_mismatch');
  if (created.status !== 'authorization_required' || created.payment_created !== true) {
    throw new Error('create_receipt_state_invalid');
  }
  if (status.status !== 'executed' || status.provider_execution_verified !== true) {
    throw new Error('provider_execution_not_verified');
  }
  if (status.value_moved !== false) throw new Error('provider_execution_must_not_claim_settlement');
  if (
    creditor.creditor_confirmation_verified !== true ||
    creditor.independently_verified !== true ||
    creditor.value_moved !== true
  ) {
    throw new Error('creditor_settlement_not_verified');
  }
  assertSame(
    creditor.provider_execution_receipt_sha256,
    statusHash,
    'creditor_provider_receipt_binding_mismatch'
  );

  const result = {
    schema: 'atlas-payment-settlement-proof-chain-v2',
    payment_id: created.payment_id,
    amount_in_minor: amount,
    currency,
    create_receipt_sha256: createHash,
    provider_execution_receipt_sha256: statusHash,
    creditor_settlement_receipt_sha256: creditorHash,
    settlement_proof_ready: true,
    value_moved: true,
    reconciled: false
  };
  result.proof_chain_sha256 = sha256(JSON.stringify(result));
  return result;
}

module.exports = { verifyReceiptHash, verifySettlementProofChain };
