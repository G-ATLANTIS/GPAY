const axios = require('axios');
const crypto = require('crypto');

const REQUEST_ID_HEADERS = [
  'x-request-id',
  'x-mollie-request-id',
  'x-correlation-id',
  'trace-id'
];

function normalizeHeaders(headers = {}) {
  const out = {};
  for (const [key, value] of Object.entries(headers)) {
    out[String(key).toLowerCase()] = Array.isArray(value) ? value.join(',') : value;
  }
  return out;
}

function extractRequestId(headers = {}) {
  const normalized = normalizeHeaders(headers);
  for (const name of REQUEST_ID_HEADERS) {
    const value = normalized[name];
    if (typeof value === 'string' && value.trim()) {
      return { requestId: value.trim(), sourceHeader: name };
    }
  }
  return { requestId: null, sourceHeader: null };
}

function buildEvidence({ provider, scope, status, headers, payload, idempotencyKey }) {
  const normalizedHeaders = normalizeHeaders(headers);
  const { requestId, sourceHeader } = extractRequestId(normalizedHeaders);
  const safeHeaders = {};
  for (const name of REQUEST_ID_HEADERS.concat(['idempotent-replayed', 'date'])) {
    if (normalizedHeaders[name] !== undefined) safeHeaders[name] = normalizedHeaders[name];
  }
  return {
    schema: 'g-provider-http-evidence-v1',
    version: '2.4.0',
    provider,
    provider_scope: scope,
    http_status: status,
    explicit_success: Number(status) >= 200 && Number(status) < 300,
    provider_request_id: requestId,
    provider_request_id_source: sourceHeader,
    provider_request_id_exposed: Boolean(requestId),
    idempotency_key: idempotencyKey,
    response_metadata: safeHeaders,
    response_payload: payload && typeof payload === 'object' ? payload : {},
    production_binding_verified: Boolean(requestId) && Number(status) >= 200 && Number(status) < 300
  };
}

async function createMolliePaymentWithEvidence(paymentRequest, options = {}) {
  const apiKey = options.apiKey || process.env.MOLLIE_API_KEY;
  if (!apiKey) throw new Error('MOLLIE_API_KEY missing');
  const idempotencyKey = options.idempotencyKey || crypto.randomUUID();
  const client = options.httpClient || axios;

  const response = await client.post(
    'https://api.mollie.com/v2/payments',
    paymentRequest,
    {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': idempotencyKey
      },
      validateStatus: () => true,
      timeout: Number(options.timeoutMs || process.env.G_MOLLIE_HTTP_TIMEOUT_MS || 15000)
    }
  );

  const evidence = buildEvidence({
    provider: 'mollie',
    scope: 'payments:write',
    status: response.status,
    headers: response.headers,
    payload: response.data,
    idempotencyKey
  });

  if (!evidence.explicit_success) {
    const err = new Error(`Mollie payment request failed with HTTP ${response.status}`);
    err.providerEvidence = evidence;
    throw err;
  }

  return { payment: response.data, evidence };
}

module.exports = {
  REQUEST_ID_HEADERS,
  normalizeHeaders,
  extractRequestId,
  buildEvidence,
  createMolliePaymentWithEvidence
};
