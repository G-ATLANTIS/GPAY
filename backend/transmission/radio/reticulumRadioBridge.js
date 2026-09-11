'use strict';

class ReticulumRadioBridge {
  constructor({ reticulumAdapter, radioBackend, destinationPolicyRegistry = null, receiptSink = null }) {
    if (!reticulumAdapter) throw new Error('reticulumAdapter is required');
    if (!radioBackend) throw new Error('radioBackend is required');
    this.reticulumAdapter = reticulumAdapter;
    this.radioBackend = radioBackend;
    this.destinationPolicyRegistry = destinationPolicyRegistry;
    this.receiptSink = receiptSink;
  }

  async verify() {
    const reticulum = await this.reticulumAdapter.probe();
    const radio = await this.radioBackend.verify();
    const receipt = {
      action: 'bridge.verify',
      status: 'VERIFIED_EXECUTED',
      bearer: this.radioBackend.kind || this.radioBackend.constructor.name,
      reticulum,
      radio,
      timestamp: new Date().toISOString(),
    };
    if (this.receiptSink) await this.receiptSink(receipt);
    return receipt;
  }

  async transmit({ payload, destination, destinationId = null, routeId = null, parameters = {} }) {
    if (!destination) throw new Error('destination is required');
    if (!this.radioBackend.verified) {
      const error = new Error('radio backend has not passed verification');
      error.code = 'G_RADIO_NOT_VERIFIED';
      throw error;
    }

    let routeAuthorization = null;
    if (this.destinationPolicyRegistry) {
      if (!destinationId || !routeId) {
        const error = new Error('destinationId and routeId are required when destination policy is enabled');
        error.code = 'G_ROUTE_POLICY_REQUIRED';
        throw error;
      }
      routeAuthorization = this.destinationPolicyRegistry.authorize({
        routeId,
        destinationId,
        address: destination,
        backendKind: this.radioBackend.kind || this.radioBackend.constructor.name,
      });
    }

    const result = await this.radioBackend.transmit({ payload, destination, parameters });
    const receipt = {
      action: 'bridge.transmit',
      status: 'VERIFIED_EXECUTED',
      bearer: this.radioBackend.kind || this.radioBackend.constructor.name,
      destination,
      destinationId,
      routeId,
      destinationPolicyHash: routeAuthorization ? routeAuthorization.destinationPolicyHash : null,
      routePolicyHash: routeAuthorization ? routeAuthorization.routePolicyHash : null,
      providerRequestId: result && result.providerRequestId ? result.providerRequestId : null,
      result,
      timestamp: new Date().toISOString(),
    };
    if (this.receiptSink) await this.receiptSink(receipt);
    return receipt;
  }
}

module.exports = { ReticulumRadioBridge };
