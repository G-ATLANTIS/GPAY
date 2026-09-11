'use strict';

const crypto = require('crypto');

function hash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

class HostAttestationImport {
  constructor({ now = Date.now, maxAgeMs = 300000 } = {}) {
    this.now = now;
    this.maxAgeMs = maxAgeMs;
    this.seenNonces = new Set();
  }

  import(attestation) {
    if (!attestation || typeof attestation !== 'object') throw new Error('attestation is required');
    const required = ['hostId', 'nonce', 'observedAt', 'status', 'evidenceHash'];
    for (const field of required) {
      if (!attestation[field]) throw new Error(`${field} is required`);
    }
    if (!['OBSERVED_NO_EXECUTION', 'READY_NO_SEND'].includes(attestation.status)) {
      const err = new Error('Unsupported host attestation status');
      err.code = 'G_HOST_ATTESTATION_STATUS_DENIED';
      throw err;
    }
    if (attestation.transmitted !== false) {
      const err = new Error('Imported host attestation must be non-transmitting');
      err.code = 'G_HOST_ATTESTATION_TRANSMIT_DENIED';
      throw err;
    }
    if (this.seenNonces.has(attestation.nonce)) {
      const err = new Error('Host attestation replay detected');
      err.code = 'G_HOST_ATTESTATION_REPLAY';
      throw err;
    }

    const observedAtMs = Date.parse(attestation.observedAt);
    if (!Number.isFinite(observedAtMs)) throw new Error('observedAt must be a valid timestamp');
    const ageMs = this.now() - observedAtMs;
    if (ageMs < -30000 || ageMs > this.maxAgeMs) {
      const err = new Error('Host attestation is outside freshness window');
      err.code = 'G_HOST_ATTESTATION_STALE';
      throw err;
    }

    const normalized = {
      hostId: attestation.hostId,
      nonce: attestation.nonce,
      observedAt: attestation.observedAt,
      importedAt: new Date(this.now()).toISOString(),
      status: attestation.status,
      transmitted: false,
      evidenceHash: attestation.evidenceHash,
      provenance: attestation.provenance || 'UNSPECIFIED_LOCAL_HOST',
      deviceFingerprint: attestation.deviceFingerprint || null,
      backendId: attestation.backendId || null,
      backendKind: attestation.backendKind || null,
      authorizationGranted: false,
      executionEligible: false,
    };

    this.seenNonces.add(attestation.nonce);
    return Object.freeze({ ...normalized, importHash: hash(normalized) });
  }
}

module.exports = { HostAttestationImport, hash };
