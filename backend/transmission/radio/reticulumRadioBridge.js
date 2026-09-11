'use strict';

class ReticulumRadioBridge {
  constructor({ reticulumAdapter, radioBackend, receiptSink = null }) {
    if (!reticulumAdapter) throw new Error('reticulumAdapter is required');
    if (!radioBackend) throw new Error('radioBackend is required');
    this.reticulumAdapter = reticulumAdapter;
    this.radioBackend = radioBackend;
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

  async transmit({ payload, destination }) {
    if (!destination) throw new Error('destination is required');
    if (!this.radioBackend.verified) {
      const error = new Error('radio backend has not passed verification');
      error.code = 'G_RADIO_NOT_VERIFIED';
      throw error;
    }
    const result = await this.radioBackend.transmit(payload, destination);
    const receipt = {
      action: 'bridge.transmit',
      status: 'VERIFIED_EXECUTED',
      bearer: this.radioBackend.kind || this.radioBackend.constructor.name,
      destination,
      providerRequestId: result && result.providerRequestId ? result.providerRequestId : null,
      result,
      timestamp: new Date().toISOString(),
    };
    if (this.receiptSink) await this.receiptSink(receipt);
    return receipt;
  }
}

module.exports = { ReticulumRadioBridge };
