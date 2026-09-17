#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const { sha256 } = require('./atlas-open-banking-core');

function requireHash(value, field) {
  const text = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(text)) throw new Error(`${field}_invalid`);
  return text;
}

function requireText(value, field, max = 256) {
  const text = String(value ?? '').trim();
  if (!text || text.length > max || /[\r\n]/.test(text)) throw new Error(`${field}_invalid`);
  return text;
}

function createConsentReceipt(input = {}) {
  const now = input.now instanceof Date ? input.now : new Date();
  const expiresAt = new Date(now.getTime() + Math.min(Number(input.ttl_seconds || 300), 900) * 1000);
  const record = {
    schema: 'atlas-open-banking-consent-v1',
    consent_id: crypto.randomUUID(),
    intent_binding_sha256: requireHash(input.intent_binding_sha256, 'intent_binding_sha256'),
    owner_approval_sha256: requireHash(input.owner_approval_sha256, 'owner_approval_sha256'),
    beneficiary_binding_sha256: requireHash(input.beneficiary_binding_sha256, 'beneficiary_binding_sha256'),
    invoice_sha256: requireHash(input.invoice_sha256, 'invoice_sha256'),
    amount_in_minor: Number(input.amount_in_minor),
    currency: requireText(input.currency || 'EUR', 'currency', 3).toUpperCase(),
    regulatory_provider: requireText(input.regulatory_provider, 'regulatory_provider', 80),
    issued_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    single_use: true,
    bank_credentials_stored: false
  };
