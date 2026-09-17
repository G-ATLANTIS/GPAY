#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');

const ADAPTER_TYPES = Object.freeze([
  'BANK_NATIVE',
  'OWN_PISP',
  'SPONSORED_PISP',
  'OUTBOUND_PROVIDER',
  'DIRECT_SEPA'
]);

function sha256(value) {
  return crypto.createHash('sha256').update(String(value ?? '')).digest('hex');
}

function requireText(value, field, max = 256) {
  const text = String(value ?? '').trim();
  if (!text || text.length > max || /[\r\n]/.test(text)) {
    throw new Error(`${field}_invalid`);
  }
  return text;
}

function requireAmount(value) {
  const amount = Number(value);
  if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('amount_in_minor_invalid');
  return amount;
}
function normalizeIntent(input = {}) {
  const amount = requireAmount(input.amount_in_minor);
  const currency = requireText(input.currency || 'EUR', 'currency', 3).toUpperCase();
  if (currency !== 'EUR') throw new Error('currency_not_supported');
  const intent = {
    intent_id: requireText(input.intent_id, 'intent_id', 128),
    amount_in_minor: amount,
    currency,
    beneficiary_name: requireText(input.beneficiary_name, 'beneficiary_name', 160),
    beneficiary_iban_sha256: requireText(input.beneficiary_iban_sha256, 'beneficiary_iban_sha256', 64),
    reference: requireText(input.reference, 'reference', 140),
    owner_approval_sha256: requireText(input.owner_approval_sha256, 'owner_approval_sha256', 64),
    invoice_sha256: requireText(input.invoice_sha256, 'invoice_sha256', 64)
  };
  if (!/^[0-9a-f]{64}$/i.test(intent.beneficiary_iban_sha256)) throw new Error('beneficiary_iban_hash_invalid');
  if (!/^[0-9a-f]{64}$/i.test(intent.owner_approval_sha256)) throw new Error('owner_approval_hash_invalid');
  if (!/^[0-9a-f]{64}$/i.test(intent.invoice_sha256)) throw new Error('invoice_hash_invalid');
  intent.intent_binding_sha256 = sha256(JSON.stringify(intent));
  return Object.freeze(intent);
}

class OpenBankingAdapter {
  constructor({ id, type, priority = 100 }) {
    this.id = requireText(id, 'adapter_id', 80);
    if (!ADAPTER_TYPES.includes(type)) throw new Error('adapter_type_invalid');
    this.type = type;
    this.priority = Number(priority);
  }
  capabilitySnapshot() { throw new Error('capabilitySnapshot_not_implemented'); }
  buildInitiationRequest() { throw new Error('buildInitiationRequest_not_implemented'); }
  normalizeStatus() { throw new Error('normalizeStatus_not_implemented'); }
}

function routeIntent({ intent, adapters, now = new Date() }) {
  const normalized = normalizeIntent(intent);
  if (!Array.isArray(adapters) || adapters.length === 0) throw new Error('adapters_required');
  const evaluated = adapters.map(adapter => {
    const cap = adapter.capabilitySnapshot({ intent: normalized, now });
    const blockers = Array.isArray(cap.blockers) ? cap.blockers.slice() : [];
    if (cap.environment !== 'PRODUCTION') blockers.push('PRODUCTION_ENVIRONMENT_REQUIRED');
    if (cap.authenticated !== true) blockers.push('AUTHENTICATION_REQUIRED');
    if (cap.execution_authorized !== true) blockers.push('EXECUTION_AUTHORIZATION_REQUIRED');
    if (cap.currency !== 'EUR') blockers.push('EUR_CAPABILITY_REQUIRED');
    if (!Number.isSafeInteger(cap.max_amount_in_minor) || cap.max_amount_in_minor < normalized.amount_in_minor) {
      blockers.push('AMOUNT_NOT_COVERED');
    }
    return { adapter, cap, blockers: [...new Set(blockers)].sort() };
  });
  const eligible = evaluated.filter(x => x.blockers.length === 0)
    .sort((a, b) => a.adapter.priority - b.adapter.priority || a.adapter.id.localeCompare(b.adapter.id));
  return {
    schema: 'atlas-open-banking-route-v1',
    intent_binding_sha256: normalized.intent_binding_sha256,
    selected_adapter_id: eligible[0]?.adapter.id || null,
    selected_adapter_type: eligible[0]?.adapter.type || null,
    decision: eligible.length ? 'EXECUTION_CANDIDATE' : 'BLOCKED',
    evaluated: evaluated.map(x => ({ adapter_id: x.adapter.id, adapter_type: x.adapter.type, blockers: x.blockers })),
    provider_call_permitted: false,
    value_moved: false
  };
}

module.exports = { ADAPTER_TYPES, OpenBankingAdapter, normalizeIntent, routeIntent, sha256 };
