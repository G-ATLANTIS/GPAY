'use strict';

const crypto = require('crypto');

function stableHash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

class DeviceBackendBindingRegistry {
  constructor({ deviceRegistry } = {}) {
    if (!deviceRegistry) throw new Error('deviceRegistry is required');
    this.deviceRegistry = deviceRegistry;
    this.bindings = new Map();
  }

  bind({ deviceFingerprint, backendId, backendKind }) {
    if (!deviceFingerprint || !backendId || !backendKind) {
      throw new Error('deviceFingerprint, backendId and backendKind are required');
    }
    if (!this.deviceRegistry.isAllowed(deviceFingerprint)) {
      const err = new Error('Device is not allowlisted');
      err.code = 'G_DEVICE_NOT_ALLOWLISTED';
      throw err;
    }

    const binding = Object.freeze({
      deviceFingerprint,
      backendId,
      backendKind,
      bindingHash: stableHash({ deviceFingerprint, backendId, backendKind }),
      createdAt: new Date().toISOString(),
    });

    this.bindings.set(backendId, binding);
    return binding;
  }

  assertBound({ backendId, deviceFingerprint }) {
    const binding = this.bindings.get(backendId);
    if (!binding) {
      const err = new Error('Backend is not bound to an approved device');
      err.code = 'G_BACKEND_UNBOUND';
      throw err;
    }
    if (binding.deviceFingerprint !== deviceFingerprint) {
      const err = new Error('Backend device fingerprint mismatch');
      err.code = 'G_DEVICE_BINDING_MISMATCH';
      throw err;
    }
    if (!this.deviceRegistry.isAllowed(deviceFingerprint)) {
      const err = new Error('Bound device is no longer allowlisted');
      err.code = 'G_DEVICE_NOT_ALLOWLISTED';
      throw err;
    }
    return binding;
  }

  attestRoute({ backendId, deviceFingerprint, routeId, bearer }) {
    const binding = this.assertBound({ backendId, deviceFingerprint });
    const attestation = {
      routeId,
      bearer,
      backendId,
      backendKind: binding.backendKind,
      deviceFingerprint,
      bindingHash: binding.bindingHash,
      verifiedAt: new Date().toISOString(),
    };
    return Object.freeze({ ...attestation, attestationHash: stableHash(attestation) });
  }

  revokeBackend(backendId) {
    return this.bindings.delete(backendId);
  }
}

module.exports = { DeviceBackendBindingRegistry, stableHash };
