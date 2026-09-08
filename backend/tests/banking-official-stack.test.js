const assert = require('node:assert/strict');

const envSnapshot = { ...process.env };

try {
  process.env.TRUELAYER_ENV = 'sandbox';
  process.env.G_BANK_ENABLE_LIVE = 'false';

  const mod = require('../../scripts/test-official-truelayer-stack');

  assert.doesNotThrow(() => mod.requireSandboxSafety());

  const paymentId = '6b9dffc2-b64f-4c63-88d1-c44be06a91ad';
  assert.equal(
    mod.parseCreatedPaymentId(`Creating external account payment\nCreated payment with id ${paymentId}\nCompleted\n`),
    paymentId
  );

  const success = mod.officialRouterObservation(
    `Type: payment_executed, Event id: e, Payment id: ${paymentId}, => http://127.0.0.1:4000/api/open-banking/webhook, SUCCESS\n`,
    paymentId
  );
  assert.equal(success.seen, true);
  assert.equal(success.success, true);
  assert.equal(success.failure, false);

  const failure = mod.officialRouterObservation(
    `Type: payment_executed, Event id: e, Payment id: ${paymentId}, => http://127.0.0.1:4000/api/open-banking/webhook, FAILURE, status: 401\n`,
    paymentId
  );
  assert.equal(failure.seen, true);
  assert.equal(failure.success, false);
  assert.equal(failure.failure, true);

  const queuedFailureId = '06b4e1b5-f9d7-4b6f-a6b6-e9ba97b9665c';
  const blocking = mod.latestOfficialRouterFailure(
    `Type: payment_failed, Event id: old, Payment id: ${queuedFailureId}, => http://127.0.0.1:4000/api/open-banking/webhook, FAILURE, status: 401 Unauthorized\n`
  );
  assert.equal(blocking.seen, true);
  assert.equal(blocking.paymentId, queuedFailureId);

  const ansi = '\u001b[32mSUCCESS\u001b[0m';
  assert.equal(mod.stripAnsi(ansi), 'SUCCESS');

  process.env.G_BANK_ENABLE_LIVE = 'true';
  assert.throws(() => mod.requireSandboxSafety(), /refuses/i);

  console.log('G-Bank official TrueLayer stack diagnostic tests: PASS');
} finally {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  for (const [key, value] of Object.entries(envSnapshot)) {
    process.env[key] = value;
  }
}
