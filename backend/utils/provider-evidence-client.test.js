const assert = require('assert');
const {
  extractRequestId,
  buildEvidence,
  createMolliePaymentWithEvidence
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
        headers: { 'x-request-id': 'mollie-req-2' },
        data: { id: 'tr_test', _links: { checkout: { href: 'https://example.test/checkout' } } }
      };
    }
  };

  const result = await createMolliePaymentWithEvidence(
    { amount: { currency: 'EUR', value: '1.00' }, description: 'test' },
    { apiKey: 'test_key', idempotencyKey: 'idem-2', httpClient: fakeHttp }
  );
  assert.strictEqual(result.evidence.provider_request_id, 'mollie-req-2');
  assert.strictEqual(result.evidence.production_binding_verified, true);

  console.log('provider-evidence-client tests passed');
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
