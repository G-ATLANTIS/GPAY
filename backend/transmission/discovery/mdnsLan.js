'use strict';

class MdnsLanDiscoverer {
  constructor({ browse, serviceType = '_g-ether._tcp.local' } = {}) {
    if (typeof browse !== 'function') throw new Error('browse function is required');
    this.browse = browse;
    this.serviceType = serviceType;
  }

  async discover() {
    const services = await this.browse(this.serviceType);
    if (!Array.isArray(services)) throw new Error('browse() must return an array');
    return services
      .filter((s) => s && s.host && Number.isInteger(s.port))
      .map((s) => ({
        id: s.id || `${s.host}:${s.port}`,
        transport: 'mdns-lan',
        host: s.host,
        port: s.port,
        verified: false,
        metadata: s.metadata || {},
      }));
  }
}

class RadioBackend {
  constructor({ id, probe, send }) {
    if (!id || typeof probe !== 'function' || typeof send !== 'function') {
      throw new Error('id, probe and send are required');
    }
    this.id = id;
    this._probe = probe;
    this._send = send;
    this.active = false;
  }

  async verify() {
    const result = await this._probe();
    this.active = Boolean(result && result.ok === true);
    return { ...result, active: this.active };
  }

  async transmit(payload, destination) {
    if (!this.active) {
      const error = new Error(`radio backend ${this.id} has not passed verification`);
      error.code = 'G_RADIO_BACKEND_NOT_VERIFIED';
      throw error;
    }
    return this._send(payload, destination);
  }
}

module.exports = { MdnsLanDiscoverer, RadioBackend };
