'use strict';

const assert = require('assert');
const { TransmissionEtherWeb, TransportState } = require('../etherWeb');
const { ReticulumSelfHostedAdapter } = require('./reticulumSelfHosted');

(async () => {
  const calls = [];
  const exec = async (request) => {
    calls.push(request);
    return { ok: true, stdout: 'local-reticulum-ok' };
  };

  const web = new TransmissionEtherWeb();
  const adapter = web.register(new ReticulumSelfHostedAdapter({ enabled: true, exec }));
  assert.equal(adapter.state, TransportState.AUTHORIZED_UNTESTED);

  const probe = await web.probe(adapter.id);
  assert.equal(probe.ok, true);
  assert.equal(probe.mode, 'ACCOUNTLESS_SELF_HOSTED');
  assert.equal(adapter.state, TransportState.AUTHORIZED_ACTIVE);

  const send = await web.send({
    transportId: adapter.id,
    payload: 'test-payload',
    destination: 'deadbeef',
  });
  assert.equal(send.ok, true);
  assert.equal(send.mode, 'ACCOUNTLESS_SELF_HOSTED');
  assert.equal(calls[0].command, 'rnstatus');
  assert.equal(calls[1].command, 'rnprobe');

  console.log('Reticulum self-hosted adapter tests passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
