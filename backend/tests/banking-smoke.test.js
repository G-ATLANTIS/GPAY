const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const originalCwd = process.cwd();
const originalArgv = process.argv.slice();
const originalFetch = global.fetch;
const envSnapshot = { ...process.env };

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-smoke-test-'));
process.chdir(tempRoot);

process.env.TRUELAYER_ENV = 'sandbox';
process.env.G_BANK_ENABLE_LIVE = 'false';
process.env.G_BANK_ENABLE_PROVIDER_PROBE = 'true';
process.env.G_BANK_OPERATOR_SECRET = 'operator-secret-012345678901234567890123456789';
process.env.G_BANK_PROVIDER_PROBE_SECRET = 'probe-secret-012345678901234567890123456789';
process.env.G_BANK_SANDBOX_SMOKE_BENEFICIARY_IBAN = 'NL91ABNA0417164300';
process.env.G_BANK_SANDBOX_SMOKE_BENEFICIARY_NAME = 'Sandbox Beneficiary';
process.env.G_BANK_SANDBOX_SMOKE_REFERENCE = 'GBANK-SMOKE';

const calls = [];
const paymentId = '12345678-1234-4234-8234-123456789abc';
const authUrl = 'https://payment.truelayer-sandbox.com/payments#payment_id=123&resource_token=super-secret-test-token';

function mockResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() {
      return JSON.stringify(body);
    }
  };
}

global.fetch = async (url, options = {}) => {
  calls.push({ url: String(url), options });

  if (String(url).endsWith('/api/open-banking/provider-readiness')) {
    assert.equal(options.method, 'POST');
    assert.equal(
      options.headers['X-G-Bank-Operator-Authorization'],
      process.env.G_BANK_OPERATOR_SECRET
    );
    assert.equal(
      options.headers['X-G-Bank-Probe-Authorization'],
      process.env.G_BANK_PROVIDER_PROBE_SECRET
    );
    return mockResponse(200, {
      provider: 'truelayer',
      environment: 'sandbox',
      access_token_obtained: true,
      request_signature_accepted: true,
      provider_http_status: 204,
      payment_created: false,
      value_moved: false,
      verified_value_flow: false
    });
  }

  if (String(url).endsWith('/api/open-banking/create-payment')) {
    assert.equal(options.method, 'POST');
    const body = JSON.parse(options.body);
    assert.equal(body.amount_eur, '0.01');
    assert.equal(body.beneficiary.iban, 'NL91ABNA0417164300');
    assert.equal(body.user.email, 'sandbox-user@example.invalid');
    assert.match(options.headers['Idempotency-Key'], /^[0-9a-f-]{36}$/i);
    return mockResponse(201, {
      provider: 'truelayer',
      environment: 'sandbox',
      payment_id: paymentId,
      status: 'authorization_required',
      authorization_required: true,
      authorization_url: authUrl,
      verified_value_flow: false
    });
  }

  if (String(url).endsWith(`/api/open-banking/payment/${paymentId}`)) {
    return mockResponse(200, {
      provider: 'truelayer',
      environment: 'sandbox',
      payment_id: paymentId,
      status: 'executed',
      creditor_settlement_proven: false,
      verified_value_flow: false
    });
  }

  if (String(url).endsWith(`/api/open-banking/payment/${paymentId}/reconcile`)) {
    return mockResponse(200, {
      provider: 'truelayer',
      environment: 'sandbox',
      payment_id: paymentId,
      reconciliation: {
        state: 'BANK_ACCEPTED_NOT_SETTLEMENT_PROVEN'
      },
      creditor_settlement_proven: false,
      verified_value_flow: false
    });
  }

  throw new Error(`Unexpected smoke test URL: ${url}`);
};

const smoke = require('../../scripts/run-banking-sandbox-smoke');

(async () => {
  try {
    await smoke.probe();

    process.argv = ['node', 'run-banking-sandbox-smoke.js', 'create', '--confirm-sandbox-payment'];
    const created = await smoke.createPayment();
    assert.equal(created.payment_id, paymentId);

    const smokeDir = path.join(tempRoot, '.secrets', 'smoke');
    const files = fs.readdirSync(smokeDir);
    const createdArtifactName = files.find(name => name.startsWith(`payment-created-${paymentId}-`) && name.endsWith('.json'));
    const hppName = `hpp-${paymentId}.url`;
    assert.ok(createdArtifactName);
    assert.equal(files.includes(hppName), true);

    const artifactText = fs.readFileSync(path.join(smokeDir, createdArtifactName), 'utf8');
    assert.equal(artifactText.includes('resource_token'), false);
    assert.equal(artifactText.includes('super-secret-test-token'), false);
    assert.match(artifactText, /authorization_url_sha256/);

    const hppPath = path.join(smokeDir, hppName);
    const hppText = fs.readFileSync(hppPath, 'utf8');
    assert.equal(hppText.includes('super-secret-test-token'), true);
    if (process.platform !== 'win32') {
      assert.equal(fs.statSync(hppPath).mode & 0o777, 0o600);
    }

    const status = await smoke.status(paymentId);
    assert.equal(status.status, 'executed');
    assert.equal(status.verified_value_flow, false);

    const reconcile = await smoke.reconcile(paymentId);
    assert.equal(
      reconcile.reconciliation.state,
      'BANK_ACCEPTED_NOT_SETTLEMENT_PROVEN'
    );
    assert.equal(reconcile.creditor_settlement_proven, false);
    assert.equal(reconcile.verified_value_flow, false);

    process.env.TRUELAYER_ENV = 'live';
    assert.throws(() => smoke.requireSandbox(), /TRUELAYER_ENV=sandbox/);

    process.env.TRUELAYER_ENV = 'sandbox';
    process.env.G_BANK_ENABLE_LIVE = 'true';
    assert.throws(() => smoke.requireSandbox(), /G_BANK_ENABLE_LIVE=true/);

    assert.equal(calls.some(call => call.url.includes('truelayer.com/v3')), false);
    console.log('Sandbox Banking smoke runner tests: PASS');
  } finally {
    global.fetch = originalFetch;
    process.argv = originalArgv;
    process.chdir(originalCwd);
    fs.rmSync(tempRoot, { recursive: true, force: true });

    for (const key of Object.keys(process.env)) {
      if (!(key in envSnapshot)) delete process.env[key];
    }
    for (const [key, value] of Object.entries(envSnapshot)) {
      process.env[key] = value;
    }
  }
})().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
