'use strict';

const assert = require('assert');
const { TransportAdapter, TransportState, TransmissionEtherWeb } = require('./etherWeb');

class TestAdapter extends TransportAdapter {
  async probe() {
    this.assertAuthorized();
    return { ok: true, providerRequestId: 'local-test-probe' };
  }

  async send(payload, destination) {
    this.assertAuthorized();
    return { ok: true, payload, destination, providerRequestId: 'local-test-send' };
  }
}

(async () => {
  const receipts = [];
  const web = new TransmissionEtherWeb({ receiptSink: async (r) => receipts.push(r) });

  const unauthorized = web.register(new TestAdapter({ id: 'no-auth', kind: 'test' }));
  assert.equal(unauthorized.state, TransportState.AUTH_REQUIRED);
  await assert.rejects(() => web.probe('no-auth'), (e) => e.code === 'G_TRANSPORT_AUTH_REQUIRED');

  const authorized = web.register(new TestAdapter({
    id: 'authorized',
    kind: 'test',
    authorizationEvidence: { source: 'unit-test-only' },
    enabled: true,
  }));
  assert.equal(authorized.state, TransportState.AUTHORIZED_UNTESTED);

  await assert.rejects(
    () => web.send({ transportId: 'authorized', payload: 'x', destination: 'y' }),
    (e) => e.code === 'G_TRANSPORT_NOT_VERIFIED_ACTIVE'
  );

  await web.probe('authorized');
  assert.equal(authorized.state, TransportState.AUTHORIZED_ACTIVE);

  const result = await web.send({ transportId: 'authorized', payload: 'hello', destination: 'loopback' });
  assert.equal(result.ok, true);
  assert.ok(receipts.some((r) => r.action === 'probe' && r.status === 'VERIFIED_EXECUTED'));
  assert.ok(receipts.some((r) => r.action === 'send' && r.status === 'VERIFIED_EXECUTED'));

  console.log('G Transmission Ether Web tests passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
