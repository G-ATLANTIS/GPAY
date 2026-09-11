'use strict';

const assert = require('assert');
const { HostEvidenceResponder } = require('./hostEvidenceResponder');

(async () => {
  let enumerateCalls = 0;
  let probeCalls = 0;
  const agent = {
    hostId: 'local-host-1',
    async enumerate() {
      enumerateCalls += 1;
      return [{ hostId: 'local-host-1', path: '/dev/ttyUSB0', observed: true, authorized: false, transmitted: false }];
    },
    async probeReticulum() {
      probeCalls += 1;
      return { hostId: 'local-host-1', status: 'READY_NO_SEND', bearer: 'RETICULUM', transmitted: false, authorizationGranted: false };
    },
  };

  const now = Date.parse('2026-09-11T18:40:00Z');
  const responder = new HostEvidenceResponder({ agent, now: () => now });
  const response = await responder.respond({
    requestId: 'req-1',
    requestHash: 'hash-1',
    hostId: 'local-host-1',
    nonce: 'nonce-1',
    transmit: false,
    executionIntent: false,
    expiresAt: '2026-09-11T18:41:00Z',
  });

  assert.equal(response.requestId, 'req-1');
  assert.equal(response.nonce, 'nonce-1');
  assert.equal(response.evidence.status, 'READY_NO_SEND');
  assert.equal(response.evidence.transmitted, false);
  assert.equal(response.evidence.authorizationGranted, false);
  assert.equal(response.evidence.executionEligible, false);
  assert.equal(enumerateCalls, 1);
  assert.equal(probeCalls, 1);

  await assert.rejects(
    () => responder.respond({ requestId: 'req-2', hostId: 'other-host', nonce: 'n', transmit: false, executionIntent: false }),
    (error) => error.code === 'G_HOST_EVIDENCE_HOST_MISMATCH'
  );

  await assert.rejects(
    () => responder.respond({ requestId: 'req-3', hostId: 'local-host-1', nonce: 'n', transmit: true, executionIntent: false }),
    (error) => error.code === 'G_HOST_EVIDENCE_REQUEST_TRANSMIT_DENIED'
  );

  await assert.rejects(
    () => responder.respond({ requestId: 'req-4', hostId: 'local-host-1', nonce: 'n', transmit: false, executionIntent: false, expiresAt: '2026-09-11T18:39:00Z' }),
    (error) => error.code === 'G_HOST_EVIDENCE_REQUEST_EXPIRED'
  );

  console.log('Host evidence responder tests passed');
})();
