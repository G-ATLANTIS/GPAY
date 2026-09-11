'use strict';

const assert = require('assert');
const { DestinationPolicyRegistry } = require('./destinationPolicy');

(() => {
  const registry = new DestinationPolicyRegistry();

  const allowed = registry.allowDestination({
    destinationId: 'peer-a',
    address: 'reticulum:peer-a',
    transportKinds: ['RNODE'],
  });
  assert.ok(allowed.policyHash);

  assert.throws(
    () => registry.bindRoute({ routeId: 'route-x', destinationId: 'peer-a', backendKind: 'KISS_TNC' }),
    (err) => err && err.code === 'G_DESTINATION_TRANSPORT_DENIED'
  );

  const route = registry.bindRoute({ routeId: 'route-a', destinationId: 'peer-a', backendKind: 'RNODE' });
  assert.ok(route.routePolicyHash);

  assert.throws(
    () => registry.authorize({
      routeId: 'route-a',
      destinationId: 'peer-a',
      address: 'reticulum:peer-b',
      backendKind: 'RNODE',
    }),
    (err) => err && err.code === 'G_DESTINATION_ADDRESS_MISMATCH'
  );

  const auth = registry.authorize({
    routeId: 'route-a',
    destinationId: 'peer-a',
    address: 'reticulum:peer-a',
    backendKind: 'RNODE',
  });
  assert.strictEqual(auth.routePolicyHash, route.routePolicyHash);
  assert.strictEqual(auth.destinationPolicyHash, allowed.policyHash);

  registry.revokeDestination('peer-a');
  assert.throws(
    () => registry.authorize({
      routeId: 'route-a',
      destinationId: 'peer-a',
      address: 'reticulum:peer-a',
      backendKind: 'RNODE',
    }),
    (err) => err && err.code === 'G_DESTINATION_NOT_ALLOWED'
  );

  console.log('G Ether Web destination policy tests passed');
})();
