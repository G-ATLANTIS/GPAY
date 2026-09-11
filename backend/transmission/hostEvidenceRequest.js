'use strict';

const crypto = require('crypto');

function sha256(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

class HostEvidenceRequestRegistry {
  constructor({ now = Date.now, ttlMs = 120000 } = {}) {
    this.now = now;
    this.ttlMs = ttlMs;
    this.requests = new Map();
  }

  create({ hostId, requestedKinds = ['SERIAL', 'RNODE', 'KISS_TNC'], nonce = crypto.randomBytes(16).toString('hex') } = {}) {
    if (!hostId) throw new Error('hostId is required');
    const createdAtMs = this.now();
    const request = {
      requestId: sha256({ hostId, nonce, createdAtMs }),
      hostId,
      nonce,
      requestedKinds: [...requestedKinds],
      askFor: ['DEVICE_ENUMERATION', 'READY_NO_SEND_PROBE'],
      transmit: false,
      executionIntent: false,
      authorizationGranted: false,
      createdAt: new Date(createdAtMs).toISOString(),
      expiresAt: new Date(createdAtMs + this.ttlMs).toISOString(),
    };
    const frozen = Object.freeze({ ...request, requestHash: sha256(request) });
    this.requests.set(frozen.requestId, frozen);
    return frozen;
  }

  assertActive(requestId) {
    const request = this.requests.get(requestId);
    if (!request) {
      const err = new Error('Host evidence request not found');
      err.code = 'G_HOST_EVIDENCE_REQUEST_NOT_FOUND';
      throw err;
    }
    if (Date.parse(request.expiresAt) < this.now()) {
      const err = new Error('Host evidence request expired');
      err.code = 'G_HOST_EVIDENCE_REQUEST_EXPIRED';
      throw err;
    }
    return request;
  }

  acceptResponse({ requestId, nonce, hostId, evidence }) {
    const request = this.assertActive(requestId);
    if (request.nonce !== nonce || request.hostId !== hostId) {
      const err = new Error('Host evidence response does not match request');
      err.code = 'G_HOST_EVIDENCE_RESPONSE_MISMATCH';
      throw err;
    }
    if (!evidence || evidence.transmitted !== false) {
      const err = new Error('Host evidence response must be non-transmitting');
      err.code = 'G_HOST_EVIDENCE_TRANSMIT_DENIED';
      throw err;
    }
    this.requests.delete(requestId);
    return Object.freeze({
      requestId,
      requestHash: request.requestHash,
      hostId,
      nonce,
      evidence,
      authorizationGranted: false,
      executionEligible: false,
      acceptedAt: new Date(this.now()).toISOString(),
      responseHash: sha256({ requestId, hostId, nonce, evidence }),
    });
  }
}

module.exports = { HostEvidenceRequestRegistry, sha256 };
