'use strict';

const assert = require('assert');
const { TransmissionEtherWeb } = require('./etherWeb');
const { HttpRelayAdapter, StarlinkEnterpriseAdapter } = require('./providers');
const { MultipathRouter } = require('./router');

function response({ status = 200, body = {} } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() { return JSON.stringify(body); },
  };
}

(async () => {
  const calls = [];
  const fakeHttp = async (url, options) => {
    calls.push({ url, options });
    if (url.includes('relay-a')) return response({ status: 503, body: { unavailable: true } });
    return response({ status: 200, body: { accepted: true, receiptId: 'relay-b-test' } });
  };

  const web = new TransmissionEtherWeb();
  const auth = { source: 'unit-test', scope: 'relay' };
  const relayA = web.register(new HttpRelayAdapter({
    id: 'relay-a', relayUrl: 'https://relay-a.invalid/ingress', authorizationEvidence: auth, enabled: true, httpClient: fakeHttp,
  }));
  const relayB = web.register(new HttpRelayAdapter({
    id: 'relay-b', relayUrl: 'https://relay-b.invalid/ingress', authorizationEvidence: auth, enabled: true, httpClient: fakeHttp,
  }));

  // HEAD probes: relay-a intentionally fails, relay-b succeeds.
  await assert.rejects(() => web.probe('relay-a'));
  await web.probe('relay-b');

  const router = new MultipathRouter({ web });
  const routed = await router.send({
    payload: { hello: 'ether-web' },
    destination: 'node:test',
    metrics: {
      'relay-a': { latencyMs: 5, lossPct: 0, trustScore: 100, availabilityScore: 100, costScore: 1 },
      'relay-b': { latencyMs: 25, lossPct: 0, trustScore: 90, availabilityScore: 100, costScore: 2 },
    },
  });
  assert.equal(routed.transportId, 'relay-b');
  assert.equal(routed.result.ok, true);
  assert.ok(calls.some((call) => call.options.method === 'POST'));

  let starlinkProbeCount = 0;
  const starlink = web.register(new StarlinkEnterpriseAdapter({
    authorizationEvidence: { source: 'unit-test', scope: 'telemetry' },
    enabled: true,
    telemetryProbe: async () => {
      starlinkProbeCount += 1;
      return { ok: true, terminalCount: 1, providerRequestId: 'starlink-test-probe' };
    },
  }));
  await web.probe(starlink.id);
  assert.equal(starlinkProbeCount, 1);
  await assert.rejects(
    () => web.send({ transportId: starlink.id, payload: 'x', destination: 'y' }),
    (error) => error.code === 'G_STARLINK_USE_BEARER_RELAY'
  );

  console.log('G Transmission Ether Web router/provider tests passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
