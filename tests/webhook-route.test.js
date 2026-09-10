const test = require('node:test');
const assert = require('node:assert/strict');

function listen(app) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
    server.on('error', reject);
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close(err => (err ? reject(err) : resolve()));
  });
}

test('webhook route is mounted and app import does not require Mollie credentials', async () => {
  const originalKey = process.env.MOLLIE_API_KEY;
  delete process.env.MOLLIE_API_KEY;

  const app = require('../backend/index');
  const server = await listen(app);
  const { port } = server.address();

  try {
    const missingId = await fetch(`http://127.0.0.1:${port}/api/mollie/webhook`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(missingId.status, 400);
    assert.deepEqual(await missingId.json(), { error: 'Missing payment id' });

    const missingConfig = await fetch(`http://127.0.0.1:${port}/api/mollie/webhook`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'tr_test_route_probe' }),
    });
    assert.equal(missingConfig.status, 503);
    assert.deepEqual(await missingConfig.json(), {
      error: 'MOLLIE_API_KEY is required',
      code: 'CONFIG_ERROR',
    });
  } finally {
    await close(server);
    if (originalKey === undefined) delete process.env.MOLLIE_API_KEY;
    else process.env.MOLLIE_API_KEY = originalKey;
  }
});
