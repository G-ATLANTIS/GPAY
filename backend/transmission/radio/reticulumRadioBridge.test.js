'use strict';

const assert = require('assert');
const { ReticulumRadioBridge } = require('./reticulumRadioBridge');
const { DestinationPolicyRegistry } = require('../policy/destinationPolicy');

(async () => {
  const receipts = [];
  const reticulumAdapter = {
    async probe() { return { ok: true, mode: 'ACCOUNTLESS_SELF_HOSTED' }; },
  };
  const radioBackend = {
    kind: 'RNODE',
    verified: false,
    async verify() { this.verified = true; return { ok: true, device: '/dev/test-rnode' }; },
    async transmit({ payload, destination, parameters }) {
      assert.equal(this.verified, true);
      return { ok: true, payload, destination, parameters, providerRequestId: 'unit-test-radio-send' };
    },
  };

  const destinationPolicyRegistry = new DestinationPolicyRegistry();
  destinationPolicyRegistry.allowDestination({
    destinationId: 'peer-1',
    address: 'peer',
    transportKinds: ['RNODE'],
  });
  destinationPolicyRegistry.bindRoute({
    routeId: 'route-1',
    destinationId: 'peer-1',
    backendKind: 'RNODE',
  });

  const bridge = new ReticulumRadioBridge({
    reticulumAdapter,
    radioBackend,
    destinationPolicyRegistry,
    receiptSink: async (r) => receipts.push(r),
  });

  await assert.rejects(
    () => bridge.transmit({ payload: 'hello', destination: 'peer', destinationId: 'peer-1', routeId: 'route-1' }),
    (error) => error.code === 'G_RADIO_NOT_VERIFIED'
  );

  const verified = await bridge.verify();
  assert.equal(verified.status, 'VERIFIED_EXECUTED');
  assert.equal(radioBackend.verified, true);

  await assert.rejects(
    () => bridge.transmit({ payload: 'hello', destination: 'evil-peer', destinationId: 'peer-1', routeId: 'route-1' }),
    (error) => error.code === 'G_DESTINATION_ADDRESS_MISMATCH'
  );

  const sent = await bridge.transmit({
    payload: 'hello',
    destination: 'peer',
    destinationId: 'peer-1',
    routeId: 'route-1',
    parameters: { test: true },
  });
  assert.equal(sent.bearer, 'RNODE');
  assert.equal(sent.providerRequestId, 'unit-test-radio-send');
  assert.equal(sent.destinationId, 'peer-1');
  assert.equal(sent.routeId, 'route-1');
  assert.ok(sent.destinationPolicyHash);
  assert.ok(sent.routePolicyHash);
  assert.ok(receipts.some((r) => r.action === 'bridge.verify'));
  assert.ok(receipts.some((r) => r.action === 'bridge.transmit'));

  destinationPolicyRegistry.revokeDestination('peer-1');
  await assert.rejects(
    () => bridge.transmit({ payload: 'blocked', destination: 'peer', destinationId: 'peer-1', routeId: 'route-1' }),
    (error) => error.code === 'G_DESTINATION_NOT_ALLOWED'
  );

  console.log('Reticulum radio bridge tests passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
