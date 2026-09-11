'use strict';

const assert = require('assert');
const { LocalHostAgent } = require('./localHostAgent');

(async () => {
  const calls = [];
  const agent = new LocalHostAgent({
    hostId: 'host-1',
    listDevicePaths: async () => ['/dev/ttyUSB0', '/dev/cu.usbserial-1'],
    commandExecutor: async ({ command, args }) => {
      calls.push({ command, args });
      if (command === 'rnstatus') return { ok: true, stdout: 'reticulum-ready' };
      if (command === 'rnprobe') return { ok: true, providerRequestId: 'local-rnprobe-1' };
      return { ok: false };
    },
  });

  const devices = await agent.enumerate();
  assert.equal(devices.length, 2);
  assert.equal(devices[0].authorized, false);
  assert.equal(devices[0].transmitted, false);
  assert.equal(calls.length, 0);

  const probe = await agent.probeReticulum();
  assert.equal(probe.status, 'READY_NO_SEND');
  assert.equal(probe.transmitted, false);
  assert.equal(probe.authorizationGranted, false);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, 'rnstatus');

  await assert.rejects(
    () => agent.transmitReticulum({ destination: 'peer', payload: 'hello' }),
    (error) => error.code === 'G_HOST_AUTH_REQUIRED'
  );

  await assert.rejects(
    () => agent.transmitReticulum({ destination: 'peer', payload: 'hello', authorizationEvidence: { owner: true } }),
    (error) => error.code === 'G_HOST_EXECUTION_INTENT_REQUIRED'
  );

  const sent = await agent.transmitReticulum({
    destination: 'peer',
    payload: 'hello',
    authorizationEvidence: { owner: true },
    executionIntent: true,
  });
  assert.equal(sent.ok, true);
  assert.equal(calls.at(-1).command, 'rnprobe');

  await assert.rejects(
    () => agent.runAllowed('sh', ['-c', 'echo nope']),
    (error) => error.code === 'G_HOST_COMMAND_DENIED'
  );

  console.log('Local host agent tests passed');
})();
