'use strict';

const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('../g-bank-live-v1/canonical');

// Request-generic authorization capability for the spine.
//
// This is the generalization of backend/g-bank-live-v1/approval.js (which is
// payment-intent-specific). An authorization is a short-lived HMAC token bound
// to the EXACT canonical request: its hash, its idempotency key, the actor, the
// capability and the operation. It cannot be replayed against a different
// request, a different key, or a different actor.
//
// The signing secret lives only in the environment and is never emitted in any
// evidence record.

const SCHEMA = 'g-verified-execution-authorization/v1';
const MIN_TTL_SECONDS = 30;
const MAX_TTL_SECONDS = 900;
const MAX_CLOCK_SKEW_MS = 30_000;

function secretFromEnv(env, envKey) {
  const key = envKey || 'G_SPINE_AUTHORIZATION_SECRET';
  const secret = String((env || process.env)[key] || '');
  if (Buffer.byteLength(secret) < 32) throw new Error('authorization_secret_too_short');
  return secret;
}

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}
function fromB64url(input) {
  return Buffer.from(input, 'base64url').toString('utf8');
}
function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('base64url');
}

function bindingFields({ requestCanonicalSha256, idempotencyKey, actor, capability, operation }) {
  return {
    request_canonical_sha256: String(requestCanonicalSha256),
    idempotency_key_sha256: sha256(String(idempotencyKey)),
    actor: String(actor),
    capability: String(capability),
    operation: String(operation),
  };
}

function createAuthorization(
  { requestCanonicalSha256, idempotencyKey, actor, capability, operation, ttl_seconds = 300, now = Date.now() },
  env = process.env,
  envKey,
) {
  if (!requestCanonicalSha256) throw new Error('request_hash_required');
  if (!idempotencyKey) throw new Error('idempotency_key_required');
  if (!actor) throw new Error('actor_required');
  const ttl = Number(ttl_seconds);
  if (!Number.isSafeInteger(ttl) || ttl < MIN_TTL_SECONDS || ttl > MAX_TTL_SECONDS) {
    throw new Error('authorization_ttl_invalid');
  }
  const body = {
    schema: SCHEMA,
    authorization_id: crypto.randomUUID(),
    ...bindingFields({ requestCanonicalSha256, idempotencyKey, actor, capability, operation }),
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + ttl * 1000).toISOString(),
  };
  const encoded = b64url(canonicalJson(body));
  return `${encoded}.${sign(encoded, secretFromEnv(env, envKey))}`;
}

// Returns the frozen authorization body on success; throws otherwise.
function verifyAuthorization(
  token,
  { requestCanonicalSha256, idempotencyKey, actor, capability, operation, now = Date.now() },
  env = process.env,
  envKey,
) {
  if (typeof token !== 'string' || !token.includes('.')) throw new Error('authorization_token_invalid');
  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) throw new Error('authorization_token_invalid');
  const [encoded, suppliedMac] = parts;

  const expectedMac = sign(encoded, secretFromEnv(env, envKey));
  const a = Buffer.from(suppliedMac);
  const b = Buffer.from(expectedMac);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error('authorization_signature_invalid');
  }

  let body;
  try {
    body = JSON.parse(fromB64url(encoded));
  } catch {
    throw new Error('authorization_payload_invalid');
  }
  if (body.schema !== SCHEMA) throw new Error('authorization_schema_invalid');

  const want = bindingFields({ requestCanonicalSha256, idempotencyKey, actor, capability, operation });
  for (const field of Object.keys(want)) {
    if (body[field] !== want[field]) throw new Error(`authorization_${field}_mismatch`);
  }

  const issued = Date.parse(body.issued_at);
  const expires = Date.parse(body.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires)) {
    throw new Error('authorization_time_invalid');
  }
  if (issued > now + MAX_CLOCK_SKEW_MS) throw new Error('authorization_issued_in_future');
  if (expires <= now) throw new Error('authorization_expired');
  if (expires - issued > MAX_TTL_SECONDS * 1000) throw new Error('authorization_lifetime_too_long');

  return Object.freeze(body);
}

module.exports = { SCHEMA, createAuthorization, verifyAuthorization };
