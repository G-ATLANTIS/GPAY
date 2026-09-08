const assert = require('node:assert/strict');

const envSnapshot = { ...process.env };

process.env.TRUELAYER_ENV = 'sandbox';
process.env.G_BANK_ENABLE_LIVE = 'false';
process.env.TRUELAYER_CLIENT_ID = 'sandbox-test-client';
process.env.TRUELAYER_CLIENT_SECRET = 'synthetic-test-secret';
delete process.env.G_BANK_WEBHOOK_ROUTER_TO;

const router = require('../../scripts/route-banking-sandbox-webhooks');

function response(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() {
      return typeof body === 'string' ? body : JSON.stringify(body ?? {});
    },
    async json() {
      return body;
    }
  };
}

(async () => {
  try {
    assert.doesNotThrow(() => router.requireSandboxSafety());
    assert.equal(
      router.destinationUrl(),
      'http://127.0.0.1:4000/api/open-banking/webhook'
    );

    process.env.G_BANK_ENABLE_LIVE = 'true';
    assert.throws(() => router.requireSandboxSafety(), /refuses to run/);
    process.env.G_BANK_ENABLE_LIVE = 'false';

    process.env.G_BANK_WEBHOOK_ROUTER_TO = 'https://example.com/api/open-banking/webhook';
    assert.throws(() => router.destinationUrl(), /localhost/);

    process.env.G_BANK_WEBHOOK_ROUTER_TO = 'http://127.0.0.1:4000/wrong';
    assert.throws(() => router.destinationUrl(), /destination path/);
    delete process.env.G_BANK_WEBHOOK_ROUTER_TO;

    const filtered = router.sanitizedForwardHeaders({
      'Tl-Signature': 'signed-value',
      'Tl-Webhook-Timestamp': '2026-09-08T08:00:00Z',
      'Content-Type': 'application/json',
      Host: 'webhooks.truelayer.com',
      'Content-Length': '123',
      Connection: 'keep-alive'
    });
    assert.equal(filtered['Tl-Signature'], 'signed-value');
    assert.equal(filtered['Tl-Webhook-Timestamp'], '2026-09-08T08:00:00Z');
    assert.equal(filtered['Content-Type'], 'application/json');
    assert.equal('Host' in filtered, false);
    assert.equal('Content-Length' in filtered, false);
    assert.equal('Connection' in filtered, false);

    const tokenCalls = [];
    const token = await router.getAccessToken(async (url, options) => {
      tokenCalls.push({ url, options });
      return response(200, { access_token: 'sandbox-access-token' });
    });
    assert.equal(token, 'sandbox-access-token');
    assert.equal(tokenCalls.length, 1);
    assert.equal(tokenCalls[0].url, 'https://auth.truelayer-sandbox.com/connect/token');
    assert.equal(tokenCalls[0].options.method, 'POST');
    assert.match(tokenCalls[0].options.body, /grant_type=client_credentials/);
    assert.match(tokenCalls[0].options.body, /scope=payments/);

    const rawBody = JSON.stringify({
      type: 'payment_executed',
      event_id: '11111111-1111-4111-8111-111111111111',
      payment_id: '22222222-2222-4222-8222-222222222222'
    });

    const calls = [];
    const result = await router.runOnce('sandbox-access-token', async (url, options = {}) => {
      calls.push({ url, options });
      if (url === router.ROUTER_URL) {
        assert.equal(options.headers.Authorization, 'Bearer sandbox-access-token');
        return response(200, {
          webhooks: [{
            headers: {
              'Tl-Signature': 'real-signature-placeholder',
              'Tl-Webhook-Timestamp': '2026-09-08T08:00:00Z',
              'Content-Type': 'application/json',
              'Content-Length': String(Buffer.byteLength(rawBody))
            },
            body: rawBody
          }]
        });
      }
      if (url === router.DEFAULT_DESTINATION) {
        assert.equal(options.method, 'POST');
        assert.equal(options.body, rawBody);
        assert.equal(options.headers['Tl-Signature'], 'real-signature-placeholder');
        assert.equal(options.headers['Content-Length'], undefined);
        return response(204, '');
      }
      throw new Error('Unexpected URL: ' + url);
    });

    assert.equal(result.refreshToken, false);
    assert.equal(result.forwarded.length, 1);
    assert.equal(result.forwarded[0].type, 'payment_executed');
    assert.equal(result.forwarded[0].paymentId, '22222222-2222-4222-8222-222222222222');

    const unauthorized = await router.runOnce('expired', async (url) => {
      assert.equal(url, router.ROUTER_URL);
      return response(401, {});
    });
    assert.equal(unauthorized.refreshToken, true);
    assert.equal(unauthorized.forwarded.length, 0);

    console.log('G-Bank native webhook router tests: PASS');
  } finally {
    for (const key of Object.keys(process.env)) {
      if (!(key in envSnapshot)) delete process.env[key];
    }
    for (const [key, value] of Object.entries(envSnapshot)) {
      process.env[key] = value;
    }
  }
})().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
