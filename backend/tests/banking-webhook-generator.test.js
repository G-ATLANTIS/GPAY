const assert = require('node:assert/strict');

const envSnapshot = { ...process.env };

try {
  process.env.TRUELAYER_ENV = 'sandbox';
  process.env.G_BANK_ENABLE_LIVE = 'false';
  const generator = require('../../scripts/generate-banking-sandbox-webhook');

  assert.doesNotThrow(() => generator.requireSandboxSafety());

  const payload = generator.buildPaymentPayload();
  assert.equal(payload.amount_in_minor, 15);
  assert.equal(payload.currency, 'GBP');
  assert.equal(payload.payment_method.provider_selection.type, 'preselected');
  assert.equal(payload.payment_method.provider_selection.provider_id, 'mock-payments-gb-redirect');
  assert.equal(payload.payment_method.provider_selection.scheme_id, 'faster_payments_service');
  assert.equal(payload.payment_method.beneficiary.account_identifier.type, 'sort_code_account_number');
  assert.equal(payload.payment_method.beneficiary.account_identifier.sort_code, '000000');
  assert.equal(payload.payment_method.beneficiary.account_identifier.account_number, '12345678');

  const mockId = '11111111-1111-4111-8111-111111111111';
  const authUri =
    `https://pay-mock-connect.truelayer-sandbox.com/login/${mockId}#token=secret-mock-token`;
  const parsed = generator.parseMockAuthorizationUri(authUri);
  assert.equal(parsed.mockPaymentId, mockId);
  assert.equal(parsed.token, 'secret-mock-token');

  assert.throws(
    () => generator.parseMockAuthorizationUri(
      `https://example.com/login/${mockId}#token=secret-mock-token`
    ),
    /Unexpected TrueLayer mock authorization host/
  );

  assert.throws(
    () => generator.parseMockAuthorizationUri(
      `https://pay-mock-connect.truelayer-sandbox.com/login/${mockId}`
    ),
    /did not contain a token/
  );

  const artifact = generator.publicPaymentArtifact(
    { id: mockId, status: 'authorization_required' },
    authUri
  );
  assert.equal(artifact.environment, 'sandbox');
  assert.equal(artifact.authorization_mode, 'direct_mock');
  assert.match(artifact.authorization_flow_uri_sha256, /^[0-9a-f]{64}$/);
  assert.equal('authorization_flow_uri' in artifact, false);
  assert.equal(JSON.stringify(artifact).includes('secret-mock-token'), false);
  assert.equal(artifact.value_moved, false);
  assert.equal(artifact.verified_value_flow, false);

  process.env.G_BANK_ENABLE_LIVE = 'true';
  assert.throws(() => generator.requireSandboxSafety(), /refuses to run|sandbox-only/i);

  console.log('G-Bank provider webhook generator tests: PASS');
} finally {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  for (const [key, value] of Object.entries(envSnapshot)) {
    process.env[key] = value;
  }
}
