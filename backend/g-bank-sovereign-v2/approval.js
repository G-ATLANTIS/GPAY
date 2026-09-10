'use strict';

const crypto = require('node:crypto');
const { canonicalJson, sha256 } = require('../g-bank-live-v1/canonical');

function secret(env = process.env) {
  const value = String(env.G_BANK_SOVEREIGN_APPROVAL_SECRET || '');
  if (Buffer.byteLength(value) < 32) throw new Error('sovereign_approval_secret_too_short');
  return value;
}

function mac(payload, key) {
  return crypto.createHmac('sha256', key).update(payload).digest('base64url');
}

function encode(value) {
  return Buffer.from(canonicalJson(value)).toString('base64url');
}

function decode(value) {
  return JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
}

function createSovereignApproval({ prepared, idempotencyKey, ttl_seconds = 300, now = Date.now() }, env = process.env) {
  if (!prepared?.preparation_sha256 || !prepared?.instruction?.instruction_sha256) throw new Error('prepared_payment_required');
  if (!idempotencyKey) throw new Error('idempotency_key_required');
  const ttl = Number(ttl_seconds);
  if (!Number.isSafeInteger(ttl) || ttl < 30 || ttl > 900) throw new Error('approval_ttl_invalid');
  const body = {
    schema: 'g-bank-sovereign-approval/v2',
    approval_id: crypto.randomUUID(),
    preparation_sha256: prepared.preparation_sha256,
    instruction_sha256: prepared.instruction.instruction_sha256,
    message_sha256: prepared.iso20022.document_sha256,
    compliance_proof_sha256: prepared.compliance_proof.proof_sha256,
    source_account_id: prepared.instruction.source_account_id,
    amount_minor: prepared.instruction.amount_minor,
    currency: prepared.instruction.currency,
    scheme: prepared.instruction.scheme,
    beneficiary_binding_sha256: prepared.instruction.beneficiary_binding_sha256,
    idempotency_key_sha256: sha256(String(idempotencyKey)),
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + ttl * 1000).toISOString(),
  };
  const payload = encode(body);
  return `${payload}.${mac(payload, secret(env))}`;
}

function verifySovereignApproval(token, { prepared, idempotencyKey, now = Date.now() }, env = process.env) {
  if (typeof token !== 'string') throw new Error('approval_token_invalid');
  const parts = token.split('.');
  if (parts.length !== 2) throw new Error('approval_token_invalid');
  const [payload, supplied] = parts;
  const expected = mac(payload, secret(env));
  const a = Buffer.from(supplied);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error('approval_signature_invalid');
  let body;
  try { body = decode(payload); } catch { throw new Error('approval_payload_invalid'); }
  if (body.schema !== 'g-bank-sovereign-approval/v2') throw new Error('approval_schema_invalid');
  if (body.preparation_sha256 !== prepared.preparation_sha256) throw new Error('approval_preparation_mismatch');
  if (body.instruction_sha256 !== prepared.instruction.instruction_sha256) throw new Error('approval_instruction_mismatch');
  if (body.message_sha256 !== prepared.iso20022.document_sha256) throw new Error('approval_message_mismatch');
  if (body.compliance_proof_sha256 !== prepared.compliance_proof.proof_sha256) throw new Error('approval_compliance_mismatch');
  if (body.source_account_id !== prepared.instruction.source_account_id) throw new Error('approval_source_account_mismatch');
  if (body.amount_minor !== prepared.instruction.amount_minor || body.currency !== prepared.instruction.currency) throw new Error('approval_amount_mismatch');
  if (body.scheme !== prepared.instruction.scheme) throw new Error('approval_scheme_mismatch');
  if (body.beneficiary_binding_sha256 !== prepared.instruction.beneficiary_binding_sha256) throw new Error('approval_beneficiary_mismatch');
  if (body.idempotency_key_sha256 !== sha256(String(idempotencyKey))) throw new Error('approval_idempotency_mismatch');
  const issued = Date.parse(body.issued_at);
  const expires = Date.parse(body.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > now + 30000 || expires <= now) throw new Error('approval_expired_or_invalid');
  return Object.freeze(body);
}

module.exports = { createSovereignApproval, verifySovereignApproval };
