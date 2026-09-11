'use strict';

class LiveBearerReadiness {
  constructor({ deviceRegistry, bindingRegistry, backend } = {}) {
    if (!deviceRegistry) throw new Error('deviceRegistry is required');
    if (!bindingRegistry) throw new Error('bindingRegistry is required');
    if (!backend) throw new Error('backend is required');
    this.deviceRegistry = deviceRegistry;
    this.bindingRegistry = bindingRegistry;
    this.backend = backend;
  }

  async inspect({ deviceFingerprint, routeId = 'readiness-probe', bearer = null } = {}) {
    if (!deviceFingerprint) throw new Error('deviceFingerprint is required');

    const device = this.deviceRegistry.assertAllowed(deviceFingerprint);
    const binding = this.bindingRegistry.assertBound({
      backendId: this.backend.id,
      deviceFingerprint,
    });

    this.backend.assertAuthorized();

    const receipt = {
      action: 'bearer.readiness',
      status: 'READY_NO_SEND',
      backendId: this.backend.id,
      backendKind: this.backend.kind,
      deviceFingerprint,
      devicePath: this.backend.devicePath,
      routeId,
      bearer: bearer || this.backend.kind,
      bindingHash: binding.bindingHash,
      authorizationEvidencePresent: Boolean(this.backend.authorizationEvidence),
      executorPresent: typeof this.backend.executor === 'function',
      backendVerified: Boolean(this.backend.verified),
      device: {
        path: device.path || null,
        kind: device.kind || null,
        vendorId: device.vendorId || null,
        productId: device.productId || null,
        serialNumberPresent: Boolean(device.serialNumber),
      },
      transmitted: false,
      timestamp: new Date().toISOString(),
    };

    return Object.freeze(receipt);
  }
}

module.exports = { LiveBearerReadiness };
