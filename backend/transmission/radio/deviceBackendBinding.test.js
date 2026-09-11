'use strict';

const assert = require('assert');
const { DeviceBackendBindingRegistry } = require('./deviceBackendBinding');

class FakeDeviceRegistry {
  constructor() { this.allowed = new Set(); }
  isAllowed(fp) { return this.allowed.has(fp); }
  allow(fp) { this.allowed.add(fp); }
  revoke(fp) { this.allowed.delete(fp); }
}

(() => {
  const devices = new FakeDeviceRegistry();
  const bindings = new DeviceBackendBindingRegistry({ deviceRegistry: devices });
  const fpA = 'fp-a';
  const fpB = 'fp-b';

  assert.throws(
    () => bindings.bind({ deviceFingerprint: fpA, backendId: 'rnode-1', backendKind: 'RNODE' }),
    err => err.code === 'G_DEVICE_NOT_ALLOWLISTED'
  );

  devices.allow(fpA);
  const binding = bindings.bind({ deviceFingerprint: fpA, backendId: 'rnode-1', backendKind: 'RNODE' });
  assert.equal(binding.deviceFingerprint, fpA);
  assert.ok(binding.bindingHash);

  assert.throws(
    () => bindings.assertBound({ backendId: 'rnode-1', deviceFingerprint: fpB }),
    err => err.code === 'G_DEVICE_BINDING_MISMATCH'
  );

  const attestation = bindings.attestRoute({
    backendId: 'rnode-1',
    deviceFingerprint: fpA,
    routeId: 'route-1',
    bearer: 'reticulum-rnode',
  });
  assert.equal(attestation.backendId, 'rnode-1');
  assert.equal(attestation.deviceFingerprint, fpA);
  assert.ok(attestation.attestationHash);

  devices.revoke(fpA);
  assert.throws(
    () => bindings.assertBound({ backendId: 'rnode-1', deviceFingerprint: fpA }),
    err => err.code === 'G_DEVICE_NOT_ALLOWLISTED'
  );

  assert.equal(bindings.revokeBackend('rnode-1'), true);
  assert.throws(
    () => bindings.assertBound({ backendId: 'rnode-1', deviceFingerprint: fpA }),
    err => err.code === 'G_BACKEND_UNBOUND'
  );

  console.log('deviceBackendBinding tests passed');
})();
