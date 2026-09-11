'use strict';

const assert = require('assert');
const { ReticulumRadioBridge } = require('./reticulumRadioBridge');

(async () => {
  const receipts = [];
  const reticulumAdapter = {
    async probe() { return { ok: true, mode: 'ACCOUNTLESS_SELF_HOSTED' }; },
  };
  const radioBackend = {
    kind: 'RNODE',
    verified: false,
    async verify() { this.verified = true; return { ok: true, device: '/dev/test-rnode' }; },
    async transmit(payload, destination) {
      assert.equal(this.verified, true);
      return { ok: true, payload, destination, providerRequestId: 'unit-test-radio-send' };
    },
  };

  const bridge = new ReticulumRadioBridge({
    reticulumAdapter,
    radioBackend,
    receiptSink: async (r) => receipts.push(r),
  });

  await assert.rejects(
    () => bridge.transmit({ payload: 'hello', destination: 'peer' }),
    (error) => error.code === 'G_RADIO_NOT_VERIFIED'
  );

  const verified = await bridge.verify();
  assert.equal(verified.status, 'VERIFIED_EXECUTED');
  assert.equal(radioBackend.verified, true);

  const sent = await bridge.transmit({ payload: 'hello', destination: 'peer' });
  assert.equal(sent.bearer, 'RNODE');
  assert.equal(sent.providerRequestId, 'unit-test-radio-send');
  assert.ok(receipts.some((r) => r.action === 'bridge.verify'));
  assert.ok(receipts.some((r) => r.action === 'bridge.transmit'));

  console.log('Reticulum radio bridge tests passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
