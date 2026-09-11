'use strict';

const assert = require('assert');
const { RNodeBackend, KissTncBackend, GenericSerialBackend } = require('./serialRadioBackends');

(async () => {
  const calls = [];
  const executor = async (request) => {
    calls.push(request);
    if (request.action === 'verify') return { ok: true, device: request.devicePath };
    if (request.action === 'transmit') return { ok: true, bytes: String(request.payload).length };
    return { ok: false };
  };

  const unauthorized = new RNodeBackend({ id: 'rnode-no-auth', devicePath: '/dev/ttyUSB0', executor });
  await assert.rejects(() => unauthorized.verify(), (e) => e.code === 'G_RADIO_AUTH_REQUIRED');

  const rnode = new RNodeBackend({
    id: 'rnode-1',
    devicePath: '/dev/ttyUSB0',
    authorizationEvidence: { owner: 'operator', scope: 'local-test' },
    executor,
  });
  await assert.rejects(
    () => rnode.transmit({ payload: 'hello' }),
    (e) => e.code === 'G_RADIO_NOT_VERIFIED'
  );
  await rnode.verify();
  const tx = await rnode.transmit({ payload: 'hello', parameters: { frequencyHz: 868000000 } });
  assert.equal(tx.ok, true);

  const kiss = new KissTncBackend({
    id: 'kiss-1',
    devicePath: '/dev/ttyACM0',
    authorizationEvidence: { owner: 'operator', scope: 'local-test' },
    executor,
  });
  await kiss.verify();
  assert.equal((await kiss.transmit({ payload: Buffer.from('abc') })).ok, true);

  const serial = new GenericSerialBackend({
    id: 'serial-1',
    devicePath: '/dev/ttyS1',
    authorizationEvidence: { owner: 'operator', scope: 'local-test' },
    executor,
  });
  await serial.verify();
  assert.equal((await serial.transmit({ payload: 'x' })).ok, true);

  assert.ok(calls.some((c) => c.kind === 'RNODE' && c.action === 'verify'));
  assert.ok(calls.some((c) => c.kind === 'KISS_TNC' && c.action === 'transmit'));
  console.log('G Ether Web serial radio backend tests passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
