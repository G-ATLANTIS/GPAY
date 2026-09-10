'use strict';

const crypto = require('node:crypto');

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((out, key) => {
      out[key] = stable(value[key]);
      return out;
    }, {});
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(stable(value));
}

function sha256(value) {
  return crypto.createHash('sha256').update(
    Buffer.isBuffer(value) ? value : String(value),
  ).digest('hex');
}

function assertString(name, value, { min = 1, max = 512 } = {}) {
  if (typeof value !== 'string' || value.length < min || value.length > max) {
    throw new Error(`${name}_invalid`);
  }
  return value;
}

function normalizeIntent(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('payment_intent_invalid');
  }

  const amountMinor = Number(input.amount_minor);
  if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0) {
    throw new Error('amount_minor_invalid');
  }

  const currency = assertString('currency', String(input.currency || '').toUpperCase(), { min: 3, max: 3 });
  if (!/^[A-Z]{3}$/.test(currency)) throw new Error('currency_invalid');

  const intent = {
    schema: 'g-bank-live-payment-intent/v1',
    intent_id: assertString('intent_id', String(input.intent_id || ''), { min: 8, max: 128 }),
    amount_minor: amountMinor,
    currency,
    description: assertString('description', String(input.description || ''), { min: 1, max: 255 }),
    destination_binding: assertString('destination_binding', String(input.destination_binding || ''), { min: 3, max: 512 }),
    redirect_url: input.redirect_url ? assertString('redirect_url', String(input.redirect_url), { min: 8, max: 2048 }) : null,
    webhook_url: input.webhook_url ? assertString('webhook_url', String(input.webhook_url), { min: 8, max: 2048 }) : null,
    metadata: input.metadata && typeof input.metadata === 'object' && !Array.isArray(input.metadata) ? stable(input.metadata) : {},
  };

  if (intent.redirect_url && !/^https:\/\//i.test(intent.redirect_url)) {
    throw new Error('redirect_url_https_required');
  }
  if (intent.webhook_url && !/^https:\/\//i.test(intent.webhook_url)) {
    throw new Error('webhook_url_https_required');
  }

  intent.intent_sha256 = sha256(canonicalJson(intent));
  return Object.freeze(intent);
}

function newIdempotencyKey() {
  return crypto.randomUUID();
}

module.exports = { canonicalJson, sha256, normalizeIntent, newIdempotencyKey };
