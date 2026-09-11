'use strict';

const assert = require('assert');
const { DeviceRegistry, stableFingerprint } = require('../deviceRegistry');
const { DeviceBackendBindingRegistry } = require('./deviceBackendBinding');
const { RNodeBackend } = require('./serialRadioBackends');
const { LiveBearerReadiness } = require('./liveBearerReadiness');

(async () => {
  const device = {
    path: '/dev/test-rnode',
    kind: 'RNODE',
    vendorId: '1234',
    productId: '5678',
    serialNumber: 'TEST-ONLY',
  };
  const fingerprint = stableFingerprint(device);
  const registry = new DeviceRegistry({
    enumerator: async () => [device],
    allowlist: [fingerprint],
  });
  await registry.enumerate();

  const executorCalls = [];
  const backend = new RNodeBackend({
    id: 'radio-1',
    devicePath: device.path,
    authorizationEvidence: { scope: 'owned-test-device' },
    executor: async (request) => {
      executorCalls.push(request);
      return { ok: true };
    },
  });

  const bindings = new DeviceBackendBindingRegistry({ deviceRegistry: registry });
  bindings.bind({ deviceFingerprint: fingerprint, backendId: backend.id, backendKind: backend.kind });

  const readiness = new LiveBearerReadiness({
    deviceRegistry: registry,
    bindingRegistry: bindings,
    backend,
  });

  const result = await readiness.inspect({
    deviceFingerprint: fingerprint,
    routeId: 'route-test',
  });

  assert.equal(result.status, 'READY_NO_SEND');
  assert.equal(result.transmitted, false);
  assert.equal(result.backendId, 'radio-1');
  assert.equal(result.backendKind, 'RNODE');
  assert.equal(result.authorizationEvidencePresent, true);
  assert.equal(result.executorPresent, true);
  assert.equal(executorCalls.length, 0, 'readiness inspection must not invoke executor or transmit');

  registry.revokeFingerprint(fingerprint);
  await assert.rejects(
    () => readiness.inspect({ deviceFingerprint: fingerprint }),
    (error) => error.code === 'G_DEVICE_NOT_ALLOWLISTED'
  );

  console.log('Live bearer readiness tests passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
