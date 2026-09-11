'use strict';

const assert = require('assert');
const { PeerRegistry, AccountlessDiscovery } = require('./peerDiscovery');

(async () => {
  let now = 1000;
  const registry = new PeerRegistry({ now: () => now, ttlMs: 100 });
  const discovery = new AccountlessDiscovery({ registry });

  discovery.registerDiscoverer({
    async scan() {
      return [
        { peerId: 'peer-a', transportId: 'reticulum', address: 'abc123', verified: true },
        { peerId: 'peer-b', transportId: 'lan', address: '192.0.2.10', verified: false },
      ];
    },
  });

  const observations = await discovery.scan();
  assert.equal(observations.length, 2);
  assert.equal(registry.active().length, 2);
  assert.equal(registry.verifiedActive().length, 1);

  now += 101;
  registry.expire();
  assert.equal(registry.active().length, 0);

  console.log('G Transmission Ether Web peer discovery tests passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
