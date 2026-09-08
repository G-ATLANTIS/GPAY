const assert = require('node:assert/strict');

const envSnapshot = { ...process.env };

(async () => {
  try {
    process.env.TRUELAYER_ENV = 'sandbox';
    process.env.G_BANK_ENABLE_LIVE = 'false';

    const mod = require('../../scripts/test-official-truelayer-webhook');

    assert.doesNotThrow(() => mod.requireSandboxSafety());

    assert.equal(
      mod.parseOfficialPaymentId('Created payment with id 47c68e65-97a8-4202-9125-b32ffb0def1c'),
      '47c68e65-97a8-4202-9125-b32ffb0def1c'
    );

    assert.equal(
      mod.parseForwardedPaymentId(
        'Webhook VERIFIED/FORWARDED type=payment_executed event_id=x payment_id=47c68e65-97a8-4202-9125-b32ffb0def1c http=200'
      ),
      '47c68e65-97a8-4202-9125-b32ffb0def1c'
    );

    const capture = {
      buffer: 'router ready\nPolling for queued webhooks every 5 seconds...\n',
      exitCode: null
    };
    const ready = await mod.waitForCaptured(
      capture,
      output => output.includes('Polling for queued webhooks every 5 seconds...'),
      100,
      'test readiness'
    );
    assert.equal(ready, true);

    process.env.G_BANK_ENABLE_LIVE = 'true';
    assert.throws(() => mod.requireSandboxSafety(), /refuses/i);

    console.log('G-Bank official TrueLayer webhook diagnostic tests: PASS');
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
  process.exit(1);
});
