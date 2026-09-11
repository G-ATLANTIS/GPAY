'use strict';

const assert = require('assert');
const { HostMediatedExecutor, bindHostExecutor } = require('./hostExecutor');

(async () => {
  const calls = [];
  const host = new HostMediatedExecutor({
    enumerateDevices: async () => [{ path: '/dev/test-rnode', kind: 'RNODE' }],
    probeDevice: async (request) => {
      calls.push({ type: 'probe', request });
      return { ok: true, providerRequestId: 'probe-1' };
    },
    transmitDevice: async (request) => {
      calls.push({ type: 'transmit', request });
      return { ok: true, providerRequestId: 'send-1' };
    },
  });

  const devices = await host.enumerate();
  assert.equal(devices.length, 1);
  assert.equal(devices[0].path, '/dev/test-rnode');

  await assert.rejects(
    () => host.execute({ action: 'verify', devicePath: '/dev/test-rnode' }),
    (error) => error.code === 'G_HOST_AUTH_REQUIRED'
  );

  const verifyExecutor = bindHostExecutor(host, {
    authorizationEvidence: { source: 'user-owned-device' },
    executionIntent: false,
  });
  const verified = await verifyExecutor({ action: 'verify', devicePath: '/dev/test-rnode' });
  assert.equal(verified.ok, true);
  assert.equal(verified.transmitted, false);
  assert.equal(calls.filter((c) => c.type === 'transmit').length, 0);

  await assert.rejects(
    () => verifyExecutor({ action: 'transmit', devicePath: '/dev/test-rnode', payload: 'hello' }),
    (error) => error.code === 'G_HOST_EXECUTION_INTENT_REQUIRED'
  );
  assert.equal(calls.filter((c) => c.type === 'transmit').length, 0);

  const liveExecutor = bindHostExecutor(host, {
    authorizationEvidence: { source: 'user-owned-device' },
    executionIntent: true,
  });
  const sent = await liveExecutor({ action: 'transmit', devicePath: '/dev/test-rnode', payload: 'hello' });
  assert.equal(sent.ok, true);
  assert.equal(sent.transmitted, true);
  assert.equal(calls.filter((c) => c.type === 'transmit').length, 1);

  console.log('Host-mediated executor tests passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
