'use strict';

const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('./canonical');

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

function parseB64url(input) {
  return Buffer.from(input, 'base64url').toString('utf8');
}

function secretFromEnv(env = process.env) {
  const secret = String(env.G_BANK_APPROVAL_SECRET || '');
  if (Buffer.byteLength(secret) < 32) throw new Error('approval_secret_too_short');
  return secret;
}

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('base64url');
}

function createApproval({ intent, provider, idempotencyKey, ttl_seconds = 300, now = Date.now() }, env = process.env) {
  if (!intent?.intent_sha256) throw new Error('intent_hash_required');
  if (!provider) throw new Error('provider_required');
  if (!idempotencyKey) throw new Error('idempotency_key_required_for_approval');
  const ttl = Number(ttl_seconds);
  if (!Number.isSafeInteger(ttl) || ttl < 30 || ttl > 900) throw new Error('approval_ttl_invalid');

  const body = {
    schema: 'g-bank-live-approval/v1',
    approval_id: crypto.randomUUID(),
    intent_sha256: intent.intent_sha256,
    provider: String(provider),
    idempotency_key_sha256: sha256(String(idempotencyKey)),
    amount_minor: intent.amount_minor,
    currency: intent.currency,
    destination_binding_sha256: sha256(intent.destination_binding),
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + ttl * 1000).toISOString(),
  };
  const encoded = b64url(canonicalJson(body));
  return `${encoded}.${sign(encoded, secretFromEnv(env))}`;
}

function verifyApproval(token, { intent, provider, idempotencyKey, now = Date.now() }, env = process.env) {
  if (typeof token !== 'string' || !token.includes('.')) throw new Error('approval_token_invalid');
  if (!idempotencyKey) throw new Error('idempotency_key_required_for_approval');
  const [encoded, suppliedMac, ...rest] = token.split('.');
  if (rest.length || !encoded || !suppliedMac) throw new Error('approval_token_invalid');

  const expectedMac = sign(encoded, secretFromEnv(env));
  const a = Buffer.from(suppliedMac);
  const b = Buffer.from(expectedMac);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error('approval_signature_invalid');

  let body;
  try { body = JSON.parse(parseB64url(encoded)); } catch { throw new Error('approval_payload_invalid'); }

  if (body.schema !== 'g-bank-live-approval/v1') throw new Error('approval_schema_invalid');
  if (body.provider !== String(provider)) throw new Error('approval_provider_mismatch');
  if (body.intent_sha256 !== intent.intent_sha256) throw new Error('approval_intent_mismatch');
  if (body.idempotency_key_sha256 !== sha256(String(idempotencyKey))) throw new Error('approval_idempotency_mismatch');
  if (body.amount_minor !== intent.amount_minor || body.currency !== intent.currency) throw new Error('approval_amount_mismatch');
  if (body.destination_binding_sha256 !== sha256(intent.destination_binding)) throw new Error('approval_destination_mismatch');

  const expires = Date.parse(body.expires_at);
  const issued = Date.parse(body.issued_at);
  if (!Number.isFinite(expires) || !Number.isFinite(issued) || issued > now + 30000 || expires <= now) {
    throw new Error('approval_expired_or_invalid');
  }
  return Object.freeze(body);
}

module.exports = { createApproval, verifyApproval };
