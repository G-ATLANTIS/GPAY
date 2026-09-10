#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  createMolliePaymentWithEvidence,
  getMolliePaymentWithEvidence
} = require('../backend/utils/provider-evidence-client');

function fail(message, code = 2) {
  console.error(`BLOCKED: ${message}`);
  process.exit(code);
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function sha256(value) {
  return crypto.createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
}

async function main() {
  const apiKey = process.env.MOLLIE_API_KEY || '';
  if (!apiKey) fail('MOLLIE_API_KEY missing');
  if (!apiKey.startsWith('test_')) fail('sandbox proof requires a Mollie test API key; live keys are denied');
  if (process.env.G_MOLLIE_SANDBOX_PROOF !== 'ALLOW_TEST_PAYMENT') {
    fail('set G_MOLLIE_SANDBOX_PROOF=ALLOW_TEST_PAYMENT to authorize one test-mode payment');
  }

  const amount = process.env.G_MOLLIE_SANDBOX_AMOUNT || '1.00';
  if (!/^\d+\.\d{2}$/.test(amount)) fail('G_MOLLIE_SANDBOX_AMOUNT must use decimal format, e.g. 1.00');
  const numericAmount = Number(amount);
  if (!(numericAmount > 0 && numericAmount <= 1.00)) fail('sandbox proof amount must be > 0 and <= EUR 1.00');

  const marker = `G-MOLLIE-SANDBOX-PROOF-${new Date().toISOString()}-${crypto.randomUUID()}`;
  const idempotencyKey = crypto.randomUUID();
  const paymentRequest = {
    amount: { currency: 'EUR', value: amount },
    description: marker,
    redirectUrl: process.env.G_MOLLIE_SANDBOX_REDIRECT_URL || 'https://example.com/g-mollie-sandbox-proof',
    metadata: { proof_marker: marker }
  };

  const created = await createMolliePaymentWithEvidence(paymentRequest, { apiKey, idempotencyKey });
  const paymentId = created.payment && created.payment.id;
  if (typeof paymentId !== 'string' || !paymentId.startsWith('tr_')) fail('provider response missing Mollie payment id');

  const readback = await getMolliePaymentWithEvidence(paymentId, { apiKey });
  const markerReadback = readback.payment && readback.payment.metadata && readback.payment.metadata.proof_marker;
  const readbackMatch = readback.payment && readback.payment.id === paymentId && markerReadback === marker;
  if (!readbackMatch) fail('Mollie readback did not match payment id and proof marker');

  const proof = {
    schema: 'g-mollie-sandbox-proof-v1',
    version: '2.5.0',
    provider: 'mollie',
    mode: 'test',
    executed_at: new Date().toISOString(),
    amount: { currency: 'EUR', value: amount },
    payment_id: paymentId,
    proof_marker: marker,
    idempotency_key: idempotencyKey,
    create_http_status: created.evidence.http_status,
    create_provider_request_id: created.evidence.provider_request_id,
    create_provider_request_id_source: created.evidence.provider_request_id_source,
    create_transport_id_verified: created.evidence.provider_request_id_exposed === true,
    readback_http_status: readback.evidence.http_status,
    readback_provider_request_id: readback.evidence.provider_request_id,
    readback_provider_request_id_source: readback.evidence.provider_request_id_source,
    readback_transport_id_verified: readback.evidence.provider_request_id_exposed === true,
    readback_match: true,
    external_write_verified: true,
    production_binding_verified:
      created.evidence.provider_request_id_exposed === true &&
      readback.evidence.provider_request_id_exposed === true,
    live_value_movement: false,
    test_mode_only: true
  };
  proof.proof_hash = sha256(proof);

  const output = process.env.G_MOLLIE_SANDBOX_PROOF_OUT || path.join('evidence', 'mollie-sandbox-proof-v2-5.json');
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(proof, null, 2)}\n`, { mode: 0o600 });

  console.log(JSON.stringify({
    status: 'VERIFIED_TEST_MODE_WRITE_READBACK',
    payment_id: paymentId,
    readback_match: true,
    create_transport_id_verified: proof.create_transport_id_verified,
    readback_transport_id_verified: proof.readback_transport_id_verified,
    production_binding_verified: proof.production_binding_verified,
    proof_path: output,
    proof_hash: proof.proof_hash
  }, null, 2));
}

main().catch((error) => {
  const evidence = error && error.providerEvidence;
  if (evidence) {
    console.error(JSON.stringify({ status: 'BLOCKED_PROVIDER_ERROR', evidence }, null, 2));
  } else {
    console.error(`BLOCKED: ${error && error.message ? error.message : String(error)}`);
  }
  process.exit(1);
});
