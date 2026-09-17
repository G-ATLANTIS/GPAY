#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const {
  evaluateNetworkReadiness
} = require('../../scripts/atlas-payment-v2-network-readiness');

function response(status, body) {
  return { status, async text() { return body; } };
}

(async () => {
  const readyFetch = async url => {
    if (url.includes('/webhook')) {
      return response(200, JSON.stringify({ environment: 'live' }));
    }
    return response(200, '<html>ok</html>');
  };
  const ready = await evaluateNetworkReadiness({
    base_url: 'https://example.test',
    fetch_impl: readyFetch
  });
  assert.equal(ready.state, 'READY');
  assert.deepEqual(ready.blockers, []);
  const blockedFetch = async url => {
    if (url.includes('/webhook')) {
      return response(200, JSON.stringify({ environment: 'sandbox' }));
    }
    return response(404, 'not found');
  };
  const blocked = await evaluateNetworkReadiness({
    base_url: 'https://example.test',
    fetch_impl: blockedFetch
  });
  assert.equal(blocked.state, 'BLOCKED');
  assert(blocked.blockers.includes('PUBLIC_RETURN_URI_UNREACHABLE'));
  assert(blocked.blockers.includes('PUBLIC_WEBHOOK_NOT_LIVE_ENV'));
  assert.equal(blocked.payment_created, false);
  assert.equal(blocked.value_moved, false);

  console.log('atlas-payment-v2-network-readiness: PASS');
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
