'use strict';

const { TransportAdapter } = require('./etherWeb');

function defaultFetch() {
  if (typeof fetch !== 'function') {
    const error = new Error('global fetch is unavailable; inject httpClient');
    error.code = 'G_TRANSPORT_HTTP_CLIENT_REQUIRED';
    throw error;
  }
  return fetch;
}

async function parseResponse(response) {
  const text = await response.text();
  let body = text;
  try { body = text ? JSON.parse(text) : null; } catch (_) {}
  if (!response.ok) {
    const error = new Error(`provider request failed with HTTP ${response.status}`);
    error.code = 'G_TRANSPORT_PROVIDER_HTTP_ERROR';
    error.httpStatus = response.status;
    error.providerBody = body;
    throw error;
  }
  return { status: response.status, body };
}

class HttpRelayAdapter extends TransportAdapter {
  constructor({ id, relayUrl, authorizationEvidence, enabled = false, headers = {}, httpClient = null }) {
    super({ id, kind: 'internet-relay', authorizationEvidence, enabled });
    if (!relayUrl) throw new Error('relayUrl is required');
    this.relayUrl = relayUrl;
    this.headers = headers;
    this.httpClient = httpClient || defaultFetch();
  }

  async probe() {
    this.assertAuthorized();
    const response = await this.httpClient(this.relayUrl, {
      method: 'HEAD',
      headers: this.headers,
    });
    const result = await parseResponse(response);
    return { ok: true, endpoint: this.relayUrl, httpStatus: result.status };
  }

  async send(payload, destination) {
    this.assertAuthorized();
    const response = await this.httpClient(this.relayUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...this.headers },
      body: JSON.stringify({ destination, payload }),
    });
    const result = await parseResponse(response);
    return { ok: true, endpoint: this.relayUrl, httpStatus: result.status, providerResult: result.body };
  }
}

class StarlinkEnterpriseAdapter extends TransportAdapter {
  constructor({ id = 'starlink-enterprise', telemetryProbe, authorizationEvidence, enabled = false }) {
    super({ id, kind: 'starlink-enterprise', authorizationEvidence, enabled });
    if (typeof telemetryProbe !== 'function') throw new Error('telemetryProbe function is required');
    this.telemetryProbe = telemetryProbe;
  }

  async probe() {
    this.assertAuthorized();
    const result = await this.telemetryProbe();
    if (!result || result.ok !== true) {
      const error = new Error('Starlink telemetry probe did not verify authorized service');
      error.code = 'G_STARLINK_PROBE_FAILED';
      throw error;
    }
    return result;
  }

  async send() {
    this.assertAuthorized();
    const error = new Error('Starlink management/telemetry APIs are not a generic data-send interface; route traffic through an authorized IP relay over the Starlink bearer');
    error.code = 'G_STARLINK_USE_BEARER_RELAY';
    throw error;
  }
}

class ThingsStackAdapter extends TransportAdapter {
  constructor({ id = 'things-stack', baseUrl, apiKey, authorizationEvidence, enabled = false, probePath, downlinkUrl = null, httpClient = null }) {
    super({ id, kind: 'lorawan-things-stack', authorizationEvidence, enabled });
    if (!baseUrl || !apiKey || !probePath) throw new Error('baseUrl, apiKey and probePath are required');
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
    this.probePath = probePath;
    this.downlinkUrl = downlinkUrl;
    this.httpClient = httpClient || defaultFetch();
  }

  _headers(extra = {}) {
    return { authorization: `Bearer ${this.apiKey}`, ...extra };
  }

  async probe() {
    this.assertAuthorized();
    const response = await this.httpClient(`${this.baseUrl}${this.probePath}`, {
      method: 'GET',
      headers: this._headers(),
    });
    const result = await parseResponse(response);
    return { ok: true, httpStatus: result.status, providerResult: result.body };
  }

  async send(payload, destination) {
    this.assertAuthorized();
    if (!this.downlinkUrl) {
      const error = new Error('no authorized LoRaWAN downlink endpoint configured');
      error.code = 'G_LORAWAN_DOWNLINK_NOT_CONFIGURED';
      throw error;
    }
    const response = await this.httpClient(this.downlinkUrl, {
      method: 'POST',
      headers: this._headers({ 'content-type': 'application/json' }),
      body: JSON.stringify({ destination, payload }),
    });
    const result = await parseResponse(response);
    return { ok: true, httpStatus: result.status, providerResult: result.body };
  }
}

module.exports = { HttpRelayAdapter, StarlinkEnterpriseAdapter, ThingsStackAdapter };
