'use strict';

const assert = require('assert');
const { HostAttestationImport } = require('./hostAttestationImport');

(() => {
  const now = Date.parse('2026-09-11T18:05:00.000Z');
  const gate = new HostAttestationImport({ now: () => now, maxAgeMs: 300000 });
  const base = {
    hostId: 'host-1',
    nonce: 'nonce-1',
    observedAt: '2026-09-11T18:04:30.000Z',
    status: 'READY_NO_SEND',
    transmitted: false,
    evidenceHash: 'a'.repeat(64),
    provenance: 'LOCAL_AUTHORIZED_HOST',
    deviceFingerprint: 'fp-1',
    backendId: 'radio-1',
    backendKind: 'RNODE',
  };

  const imported = gate.import(base);
  assert.equal(imported.status, 'READY_NO_SEND');
  assert.equal(imported.transmitted, false);
  assert.equal(imported.authorizationGranted, false);
  assert.equal(imported.executionEligible, false);
  assert.equal(imported.importHash.length, 64);

  assert.throws(
    () => gate.import(base),
    (err) => err.code === 'G_HOST_ATTESTATION_REPLAY'
  );

  assert.throws(
    () => gate.import({ ...base, nonce: 'nonce-2', transmitted: true }),
    (err) => err.code === 'G_HOST_ATTESTATION_TRANSMIT_DENIED'
  );

  assert.throws(
    () => gate.import({ ...base, nonce: 'nonce-3', observedAt: '2026-09-11T17:00:00.000Z' }),
    (err) => err.code === 'G_HOST_ATTESTATION_STALE'
  );

  const observed = gate.import({
    ...base,
    nonce: 'nonce-4',
    status: 'OBSERVED_NO_EXECUTION',
    deviceFingerprint: null,
    backendId: null,
    backendKind: null,
  });
  assert.equal(observed.executionEligible, false);

  console.log('Host attestation import tests passed');
})();
