'use strict';

const assert = require('assert');
const { HostEvidenceRequestRegistry } = require('./hostEvidenceRequest');

(() => {
  let now = Date.parse('2026-09-11T18:00:00Z');
  const registry = new HostEvidenceRequestRegistry({ now: () => now, ttlMs: 1000 });

  const request = registry.create({ hostId: 'local-host-1', nonce: 'nonce-1' });
  assert.equal(request.transmit, false);
  assert.equal(request.executionIntent, false);
  assert.equal(request.authorizationGranted, false);
  assert.deepEqual(request.askFor, ['DEVICE_ENUMERATION', 'READY_NO_SEND_PROBE']);

  const accepted = registry.acceptResponse({
    requestId: request.requestId,
    nonce: 'nonce-1',
    hostId: 'local-host-1',
    evidence: {
      status: 'READY_NO_SEND',
      transmitted: false,
      deviceFingerprint: 'fp-1',
      backendKind: 'RNODE',
    },
  });
  assert.equal(accepted.authorizationGranted, false);
  assert.equal(accepted.executionEligible, false);

  const request2 = registry.create({ hostId: 'local-host-2', nonce: 'nonce-2' });
  assert.throws(
    () => registry.acceptResponse({ requestId: request2.requestId, nonce: 'wrong', hostId: 'local-host-2', evidence: { transmitted: false } }),
    (error) => error.code === 'G_HOST_EVIDENCE_RESPONSE_MISMATCH'
  );

  assert.throws(
    () => registry.acceptResponse({ requestId: request2.requestId, nonce: 'nonce-2', hostId: 'local-host-2', evidence: { transmitted: true } }),
    (error) => error.code === 'G_HOST_EVIDENCE_TRANSMIT_DENIED'
  );

  now += 1001;
  assert.throws(
    () => registry.assertActive(request2.requestId),
    (error) => error.code === 'G_HOST_EVIDENCE_REQUEST_EXPIRED'
  );

  console.log('Host evidence request tests passed');
})();
