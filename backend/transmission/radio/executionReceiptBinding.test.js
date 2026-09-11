'use strict';

const assert = require('assert');
const { ExecutionReceiptBinding } = require('./executionReceiptBinding');

(async () => {
  let allow = true;
  const bindingRegistry = {
    attestRoute({ backendId, deviceFingerprint, routeId, bearer }) {
      if (!allow) {
        const err = new Error('Bound device is no longer allowlisted');
        err.code = 'G_DEVICE_NOT_ALLOWLISTED';
        throw err;
      }
      assert.strictEqual(backendId, 'radio-1');
      assert.strictEqual(deviceFingerprint, 'fp-1');
      return {
        bindingHash: 'binding-hash',
        attestationHash: 'attestation-hash',
        routeId,
        bearer,
      };
    },
  };

  const bridge = {
    async transmit({ payload, destination }) {
      assert.deepStrictEqual(payload, { hello: 'world' });
      assert.strictEqual(destination, 'dest-1');
      return {
        providerRequestId: 'local-radio-req-1',
        result: { ok: true },
      };
    },
  };

  const emitted = [];
  const binder = new ExecutionReceiptBinding({
    bindingRegistry,
    receiptSink: async (receipt) => emitted.push(receipt),
  });

  const receipt = await binder.execute({
    bridge,
    backendId: 'radio-1',
    deviceFingerprint: 'fp-1',
    routeId: 'route-1',
    bearer: 'RNODE',
    payload: { hello: 'world' },
    destination: 'dest-1',
  });

  assert.strictEqual(receipt.status, 'VERIFIED_EXECUTED');
  assert.strictEqual(receipt.bindingHash, 'binding-hash');
  assert.strictEqual(receipt.routeAttestationHash, 'attestation-hash');
  assert.strictEqual(receipt.providerRequestId, 'local-radio-req-1');
  assert.strictEqual(receipt.deviceFingerprint, 'fp-1');
  assert.strictEqual(emitted.length, 1);
  assert.ok(/^[a-f0-9]{64}$/.test(receipt.receiptHash));

  allow = false;
  await assert.rejects(
    () => binder.execute({
      bridge,
      backendId: 'radio-1',
      deviceFingerprint: 'fp-1',
      routeId: 'route-1',
      bearer: 'RNODE',
      payload: { hello: 'world' },
      destination: 'dest-1',
    }),
    (err) => err.code === 'G_DEVICE_NOT_ALLOWLISTED',
  );

  console.log('executionReceiptBinding tests passed');
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
