'use strict';

const crypto = require('crypto');

function hashReceipt(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

class ExecutionReceiptBinding {
  constructor({ bindingRegistry, receiptSink = null } = {}) {
    if (!bindingRegistry) throw new Error('bindingRegistry is required');
    this.bindingRegistry = bindingRegistry;
    this.receiptSink = receiptSink;
  }

  async execute({ bridge, backendId, deviceFingerprint, routeId, bearer, payload, destination }) {
    if (!bridge) throw new Error('bridge is required');
    if (!backendId || !deviceFingerprint || !routeId || !bearer) {
      throw new Error('backendId, deviceFingerprint, routeId and bearer are required');
    }

    const routeAttestation = this.bindingRegistry.attestRoute({
      backendId,
      deviceFingerprint,
      routeId,
      bearer,
    });

    const transmitReceipt = await bridge.transmit({ payload, destination });
    const receipt = {
      action: 'bound.transmit',
      status: 'VERIFIED_EXECUTED',
      routeId,
      bearer,
      backendId,
      deviceFingerprint,
      bindingHash: routeAttestation.bindingHash,
      routeAttestationHash: routeAttestation.attestationHash,
      destination,
      providerRequestId: transmitReceipt.providerRequestId || null,
      transportReceipt: transmitReceipt,
      timestamp: new Date().toISOString(),
    };

    const immutableReceipt = Object.freeze({
      ...receipt,
      receiptHash: hashReceipt(receipt),
    });

    if (this.receiptSink) await this.receiptSink(immutableReceipt);
    return immutableReceipt;
  }
}

module.exports = { ExecutionReceiptBinding, hashReceipt };
