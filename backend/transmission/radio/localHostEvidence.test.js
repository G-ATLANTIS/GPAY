'use strict';

const assert = require('assert');
const { LocalHostEvidenceEnvelope } = require('./localHostEvidence');

(async () => {
  const emitted = [];
  const envelope = new LocalHostEvidenceEnvelope({
    hostId: 'host-test',
    receiptSink: async (receipt) => emitted.push(receipt),
  });

  const enumeration = await envelope.recordEnumeration({
    devices: [{
      path: '/dev/ttyUSB0',
      kind: 'RNODE',
      vendorId: 'test-vendor',
      productId: 'test-product',
      serialNumber: 'test-serial',
      fingerprint: 'fp-test',
      allowed: false,
    }],
  });

  assert.equal(enumeration.status, 'OBSERVED_NO_EXECUTION');
  assert.equal(enumeration.deviceCount, 1);
  assert.equal(enumeration.devices[0].allowed, false);
  assert.equal(enumeration.transmitted, false);
  assert.equal(enumeration.sequence, 1);
  assert.equal(enumeration.evidenceHash.length, 64);

  const probe = await envelope.recordProbe({
    backendId: 'radio-1',
    deviceFingerprint: 'fp-test',
    result: { ok: true, devicePath: '/dev/ttyUSB0', mode: 'VERIFY_ONLY' },
  });

  assert.equal(probe.status, 'READY_NO_SEND');
  assert.equal(probe.transmitted, false);
  assert.equal(probe.sequence, 2);
  assert.equal(probe.evidenceHash.length, 64);

  await assert.rejects(
    () => envelope.recordProbe({
      backendId: 'radio-1',
      deviceFingerprint: 'fp-test',
      result: { ok: false },
    }),
    (error) => error.code === 'G_HOST_PROBE_NOT_VERIFIED'
  );

  assert.equal(emitted.length, 2);
  console.log('Local host evidence envelope tests passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
