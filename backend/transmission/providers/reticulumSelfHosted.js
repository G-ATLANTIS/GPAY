'use strict';

const { TransportAdapter } = require('../etherWeb');

class ReticulumSelfHostedAdapter extends TransportAdapter {
  constructor({ id = 'reticulum-self-hosted', authorizationEvidence = { source: 'self-hosted-operator-control' }, enabled = false, exec = null, configPath = null }) {
    super({ id, kind: 'reticulum-self-hosted', authorizationEvidence, enabled });
    this.exec = exec;
    this.configPath = configPath;
  }

  _assertExecutor() {
    if (typeof this.exec !== 'function') {
      const error = new Error('no local Reticulum executor configured');
      error.code = 'G_RETICULUM_EXECUTOR_REQUIRED';
      throw error;
    }
  }

  async probe() {
    this.assertAuthorized();
    this._assertExecutor();
    const result = await this.exec({ command: 'rnstatus', args: [], configPath: this.configPath });
    if (!result || result.ok !== true) {
      const error = new Error('Reticulum probe failed');
      error.code = 'G_RETICULUM_PROBE_FAILED';
      error.result = result || null;
      throw error;
    }
    return {
      ok: true,
      transport: this.id,
      mode: 'ACCOUNTLESS_SELF_HOSTED',
      command: 'rnstatus',
      providerRequestId: null,
      evidence: result,
    };
  }

  async send(payload, destination) {
    this.assertAuthorized();
    this._assertExecutor();
    if (!destination) {
      const error = new Error('Reticulum destination is required');
      error.code = 'G_RETICULUM_DESTINATION_REQUIRED';
      throw error;
    }
    const result = await this.exec({
      command: 'rnprobe',
      args: ['--count', '1', String(destination)],
      payload,
      configPath: this.configPath,
    });
    if (!result || result.ok !== true) {
      const error = new Error('Reticulum send/probe failed');
      error.code = 'G_RETICULUM_SEND_FAILED';
      error.result = result || null;
      throw error;
    }
    return {
      ok: true,
      destination,
      mode: 'ACCOUNTLESS_SELF_HOSTED',
      evidence: result,
    };
  }
}

module.exports = { ReticulumSelfHostedAdapter };
