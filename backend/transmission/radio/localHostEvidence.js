'use strict';

const crypto = require('crypto');

function hash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

class LocalHostEvidenceEnvelope {
  constructor({ hostId, receiptSink = null } = {}) {
    if (!hostId) throw new Error('hostId is required');
    this.hostId = hostId;
    this.receiptSink = receiptSink;
    this.sequence = 0;
  }

  async recordEnumeration({ devices, source = 'LOCAL_HOST' }) {
    if (!Array.isArray(devices)) throw new Error('devices must be an array');
    const normalized = devices.map((device) => ({
      path: device.path || null,
      kind: device.kind || null,
      vendorId: device.vendorId || null,
      productId: device.productId || null,
      serialNumber: device.serialNumber || null,
      fingerprint: device.fingerprint || null,
      allowed: device.allowed === true,
    }));
    return this.#emit({
      action: 'host.enumeration',
      status: 'OBSERVED_NO_EXECUTION',
      source,
      deviceCount: normalized.length,
      devices: normalized,
      transmitted: false,
    });
  }

  async recordProbe({ backendId, deviceFingerprint, result }) {
    if (!backendId || !deviceFingerprint) throw new Error('backendId and deviceFingerprint are required');
    if (!result || result.ok !== true) {
      const err = new Error('probe result is not verified successful');
      err.code = 'G_HOST_PROBE_NOT_VERIFIED';
      throw err;
    }
    return this.#emit({
      action: 'host.probe',
      status: 'READY_NO_SEND',
      backendId,
      deviceFingerprint,
      probeResult: result,
      transmitted: false,
    });
  }

  async #emit(payload) {
    const sequence = ++this.sequence;
    const receipt = {
      hostId: this.hostId,
      sequence,
      timestamp: new Date().toISOString(),
      ...payload,
    };
    const immutable = Object.freeze({ ...receipt, evidenceHash: hash(receipt) });
    if (this.receiptSink) await this.receiptSink(immutable);
    return immutable;
  }
}

module.exports = { LocalHostEvidenceEnvelope, hash };
