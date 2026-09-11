'use strict';

const TransportState = Object.freeze({
  AUTHORIZED_ACTIVE: 'AUTHORIZED_ACTIVE',
  AUTHORIZED_UNTESTED: 'AUTHORIZED_UNTESTED',
  PUBLIC_READ_ONLY: 'PUBLIC_READ_ONLY',
  AUTH_REQUIRED: 'AUTH_REQUIRED',
  BLOCKED: 'BLOCKED',
});

class TransportAdapter {
  constructor({ id, kind, authorizationEvidence = null, enabled = false }) {
    if (!id || !kind) throw new Error('id and kind are required');
    this.id = id;
    this.kind = kind;
    this.authorizationEvidence = authorizationEvidence;
    this.enabled = Boolean(enabled);
    this.state = authorizationEvidence ? TransportState.AUTHORIZED_UNTESTED : TransportState.AUTH_REQUIRED;
  }

  assertAuthorized() {
    if (!this.enabled || !this.authorizationEvidence) {
      const error = new Error(`transport ${this.id} is not authorized for execution`);
      error.code = 'G_TRANSPORT_AUTH_REQUIRED';
      throw error;
    }
  }

  async probe() {
    this.assertAuthorized();
    throw new Error('probe() must be implemented by a provider adapter');
  }

  async send(_payload, _destination) {
    this.assertAuthorized();
    throw new Error('send() must be implemented by a provider adapter');
  }

  async receive() {
    this.assertAuthorized();
    throw new Error('receive() must be implemented by a provider adapter');
  }

  async health() {
    return {
      id: this.id,
      kind: this.kind,
      enabled: this.enabled,
      state: this.state,
      authorized: Boolean(this.authorizationEvidence),
    };
  }
}

class TransmissionEtherWeb {
  constructor({ receiptSink = null } = {}) {
    this.adapters = new Map();
    this.receiptSink = receiptSink;
  }

  register(adapter) {
    if (!(adapter instanceof TransportAdapter)) throw new TypeError('adapter must extend TransportAdapter');
    if (this.adapters.has(adapter.id)) throw new Error(`duplicate transport id: ${adapter.id}`);
    this.adapters.set(adapter.id, adapter);
    return adapter;
  }

  list() {
    return [...this.adapters.values()].map((a) => ({
      id: a.id,
      kind: a.kind,
      state: a.state,
      enabled: a.enabled,
      authorized: Boolean(a.authorizationEvidence),
    }));
  }

  async probe(id) {
    const adapter = this._get(id);
    try {
      const result = await adapter.probe();
      adapter.state = TransportState.AUTHORIZED_ACTIVE;
      await this._receipt({ action: 'probe', transport: id, status: 'VERIFIED_EXECUTED', result });
      return result;
    } catch (error) {
      if (error && error.code === 'G_TRANSPORT_AUTH_REQUIRED') adapter.state = TransportState.AUTH_REQUIRED;
      await this._receipt({ action: 'probe', transport: id, status: 'VERIFIED_FAILED', error: String(error.message || error) });
      throw error;
    }
  }

  async send({ transportId, payload, destination }) {
    const adapter = this._get(transportId);
    adapter.assertAuthorized();
    if (adapter.state !== TransportState.AUTHORIZED_ACTIVE) {
      const error = new Error(`transport ${transportId} has not passed a verified probe`);
      error.code = 'G_TRANSPORT_NOT_VERIFIED_ACTIVE';
      throw error;
    }
    const result = await adapter.send(payload, destination);
    await this._receipt({ action: 'send', transport: transportId, destination, status: 'VERIFIED_EXECUTED', result });
    return result;
  }

  _get(id) {
    const adapter = this.adapters.get(id);
    if (!adapter) throw new Error(`unknown transport: ${id}`);
    return adapter;
  }

  async _receipt(entry) {
    const receipt = { ...entry, timestamp: new Date().toISOString() };
    if (this.receiptSink) await this.receiptSink(receipt);
    return receipt;
  }
}

module.exports = { TransportState, TransportAdapter, TransmissionEtherWeb };
