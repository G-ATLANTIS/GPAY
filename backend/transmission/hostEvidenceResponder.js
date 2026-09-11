'use strict';

class HostEvidenceResponder {
  constructor({ agent, now = Date.now } = {}) {
    if (!agent) throw new Error('agent is required');
    this.agent = agent;
    this.now = now;
  }

  async respond(request = {}) {
    if (!request.requestId || !request.hostId || !request.nonce) {
      const error = new Error('requestId, hostId and nonce are required');
      error.code = 'G_HOST_EVIDENCE_REQUEST_INVALID';
      throw error;
    }
    if (request.hostId !== this.agent.hostId) {
      const error = new Error('Evidence request host does not match local host');
      error.code = 'G_HOST_EVIDENCE_HOST_MISMATCH';
      throw error;
    }
    if (request.transmit !== false || request.executionIntent !== false) {
      const error = new Error('Evidence request must be non-transmitting');
      error.code = 'G_HOST_EVIDENCE_REQUEST_TRANSMIT_DENIED';
      throw error;
    }
    if (request.expiresAt && Date.parse(request.expiresAt) < this.now()) {
      const error = new Error('Evidence request expired');
      error.code = 'G_HOST_EVIDENCE_REQUEST_EXPIRED';
      throw error;
    }

    const devices = await this.agent.enumerate();
    let probe;
    try {
      probe = await this.agent.probeReticulum();
    } catch (error) {
      probe = Object.freeze({
        hostId: this.agent.hostId,
        status: 'BLOCKED',
        bearer: 'RETICULUM',
        transmitted: false,
        error: error.code || error.message,
      });
    }

    return Object.freeze({
      requestId: request.requestId,
      requestHash: request.requestHash || null,
      hostId: request.hostId,
      nonce: request.nonce,
      evidence: Object.freeze({
        status: probe.status === 'READY_NO_SEND' ? 'READY_NO_SEND' : 'OBSERVED_NO_EXECUTION',
        transmitted: false,
        authorizationGranted: false,
        executionEligible: false,
        devices,
        reticulum: probe,
        observedAt: new Date(this.now()).toISOString(),
      }),
    });
  }
}

module.exports = { HostEvidenceResponder };
