'use strict';

const assert = require('assert');
const { DeviceRegistry, stableFingerprint } = require('./deviceRegistry');

(async () => {
  const sample = { vendorId: '1234', productId: '5678', serialNumber: 'ABC', path: '/dev/ttyUSB0', kind: 'rnode' };
  const fingerprint = stableFingerprint(sample);
  const registry = new DeviceRegistry({ enumerator: async () => [sample] });

  const devices = await registry.enumerate();
  assert.equal(devices.length, 1);
  assert.equal(devices[0].allowed, false);
  assert.throws(() => registry.assertAllowed(fingerprint), (e) => e.code === 'G_DEVICE_NOT_ALLOWLISTED');

  registry.authorizeFingerprint(fingerprint);
  assert.equal(registry.assertAllowed(fingerprint).path, '/dev/ttyUSB0');

  registry.revokeFingerprint(fingerprint);
  assert.throws(() => registry.assertAllowed(fingerprint), (e) => e.code === 'G_DEVICE_NOT_ALLOWLISTED');

  const registry2 = new DeviceRegistry({ enumerator: async () => [sample], allowlist: [fingerprint] });
  const devices2 = await registry2.enumerate();
  assert.equal(devices2[0].allowed, true);

  console.log('G Transmission Ether Web device registry tests passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
