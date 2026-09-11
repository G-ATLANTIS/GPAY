'use strict';

const assert = require('assert');
const { MdnsLanDiscoverer, RadioBackend } = require('./mdnsLan');

(async () => {
  const discoverer = new MdnsLanDiscoverer({
    browse: async (serviceType) => {
      assert.equal(serviceType, '_g-ether._tcp.local');
      return [
        { id: 'peer-a', host: '192.168.1.10', port: 7447, metadata: { source: 'local-test' } },
        { host: 'bad-peer', port: '7447' },
      ];
    },
  });

  const peers = await discoverer.discover();
  assert.equal(peers.length, 1);
  assert.equal(peers[0].id, 'peer-a');
  assert.equal(peers[0].verified, false);

  const sent = [];
  const radio = new RadioBackend({
    id: 'owned-rnode',
    probe: async () => ({ ok: true, device: 'test-rnode' }),
    send: async (payload, destination) => {
      sent.push({ payload, destination });
      return { ok: true };
    },
  });

  await assert.rejects(() => radio.transmit('x', 'y'), (e) => e.code === 'G_RADIO_BACKEND_NOT_VERIFIED');
  const verified = await radio.verify();
  assert.equal(verified.active, true);
  const result = await radio.transmit('hello', 'peer-a');
  assert.equal(result.ok, true);
  assert.equal(sent.length, 1);

  console.log('G Ether Web mDNS/radio tests passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
