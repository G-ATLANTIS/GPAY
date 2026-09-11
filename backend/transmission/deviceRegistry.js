'use strict';

const crypto = require('crypto');

function stableFingerprint(device) {
  const basis = [device.vendorId || '', device.productId || '', device.serialNumber || '', device.path || '', device.kind || ''].join('|');
  return crypto.createHash('sha256').update(basis).digest('hex');
}

class DeviceRegistry {
  constructor({ enumerator, allowlist = [] } = {}) {
    if (typeof enumerator !== 'function') throw new Error('enumerator function is required');
    this.enumerator = enumerator;
    this.allowlist = new Set(allowlist);
    this.devices = new Map();
  }

  async enumerate() {
    const found = await this.enumerator();
    if (!Array.isArray(found)) throw new Error('enumerator must return an array');
    this.devices.clear();
    for (const device of found) {
      const fingerprint = stableFingerprint(device);
      this.devices.set(fingerprint, { ...device, fingerprint, allowed: this.allowlist.has(fingerprint) });
    }
    return this.list();
  }

  list() {
    return [...this.devices.values()];
  }

  authorizeFingerprint(fingerprint) {
    if (!fingerprint) throw new Error('fingerprint is required');
    this.allowlist.add(fingerprint);
    const device = this.devices.get(fingerprint);
    if (device) device.allowed = true;
  }

  revokeFingerprint(fingerprint) {
    this.allowlist.delete(fingerprint);
    const device = this.devices.get(fingerprint);
    if (device) device.allowed = false;
  }

  assertAllowed(fingerprint) {
    const device = this.devices.get(fingerprint);
    if (!device || !this.allowlist.has(fingerprint)) {
      const error = new Error('device is not allowlisted for execution');
      error.code = 'G_DEVICE_NOT_ALLOWLISTED';
      throw error;
    }
    return device;
  }
}

module.exports = { DeviceRegistry, stableFingerprint };
