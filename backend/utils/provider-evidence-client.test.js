const assert = require('assert');
const {
  extractRequestId,
  buildEvidence,
  createMolliePaymentWithEvidence,
  getMolliePaymentWithEvidence
} = require('./provider-evidence-client');

async function run() {
  assert.deepStrictEqual(
    extractRequestId({ 'X-Request-Id': 'mollie-req-1' }),
    { requestId: 'mollie-req-1', sourceHeader: 'x-request-id' }
  );

  const noId = buildEvidence({
    provider: 'mollie',
    scope: 'payments:write',
    status: 201,
    headers: { date: 'Thu, 10 Sep 2026 17:00:00 GMT' },
    payload: { id: 'tr_test' },
    idempotencyKey: 'idem-1'
  });
  assert.strictEqual(noId.explicit_success, true);
  assert.strictEqual(noId.provider_request_id_exposed, false);
  assert.strictEqual(noId.production_binding_verified, false);

  const fakeHttp = {
    async post(url, body, config) {
      assert.strictEqual(url, 'https://api.mollie.com/v2/payments');
      assert.strictEqual(config.headers.Authorization, 'Bearer test_key');
      assert.strictEqual(config.headers['Idempotency-Key'], 'idem-2');
      return {
        status: 201,
        headers: { 'x-request-id': 'mollie-create-req' },
        data: { id: 'tr_test', metadata: { proof_marker: 'marker' }, _links: { checkout: { href: 'https://example.test/checkout' } } }
      };
    },
    async get(url, config) {
      assert.strictEqual(url, 'https://api.mollie.com/v2/payments/tr_test');
      assert.strictEqual(config.headers.Authorization, 'Bearer test_key');
      return {
        status: 200,
        headers: { 'x-request-id': 'mollie-read-req' },
        data: { id: 'tr_test', status: 'open', metadata: { proof_marker: 'marker' } }
      };
    }
  };

  const created = await createMolliePaymentWithEvidence(
    { amount: { currency: 'EUR', value: '1.00' }, description: 'test', metadata: { proof_marker: 'marker' } },
    { apiKey: 'test_key', idempotencyKey: 'idem-2', httpClient: fakeHttp }
  );
  assert.strictEqual(created.evidence.provider_request_id, 'mollie-create-req');
  assert.strictEqual(created.evidence.production_binding_verified, true);
  assert.strictEqual(created.evidence.version, '2.5.0');

  const readback = await getMolliePaymentWithEvidence('tr_test', { apiKey: 'test_key', httpClient: fakeHttp });
  assert.strictEqual(readback.payment.id, 'tr_test');
  assert.strictEqual(readback.evidence.provider_scope, 'payments:read');
  assert.strictEqual(readback.evidence.provider_request_id, 'mollie-read-req');
  assert.strictEqual(readback.evidence.production_binding_verified, true);

  await assert.rejects(
    () => getMolliePaymentWithEvidence('invalid', { apiKey: 'test_key', httpClient: fakeHttp }),
    /invalid Mollie payment id/
  );

  console.log('provider-evidence-client tests passed');
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
