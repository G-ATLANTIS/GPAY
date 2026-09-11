'use strict';

const crypto = require('crypto');

function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

function publicKeyFingerprint(publicKeyPem) {
  return crypto.createHash('sha256').update(publicKeyPem).digest('hex');
}

class PeerIdentityVerifier {
  constructor({ trustedPeers = {} } = {}) {
    this.trustedPeers = new Map(Object.entries(trustedPeers));
  }

  trust({ peerId, publicKeyPem }) {
    if (!peerId || !publicKeyPem) throw new Error('peerId and publicKeyPem are required');
    const record = Object.freeze({ peerId, publicKeyPem, fingerprint: publicKeyFingerprint(publicKeyPem) });
    this.trustedPeers.set(peerId, record);
    return record;
  }

  revoke(peerId) {
    return this.trustedPeers.delete(peerId);
  }

  signablePayload({ receiptHash, attestationHash, sequence, nonce }) {
    if (!receiptHash || !attestationHash || !Number.isInteger(sequence) || sequence < 1 || !nonce) {
      throw new Error('receiptHash, attestationHash, positive sequence and nonce are required');
    }
    return canonical({ receiptHash, attestationHash, sequence, nonce });
  }

  verify({ peerId, receiptHash, attestationHash, sequence, nonce, signature }) {
    const peer = this.trustedPeers.get(peerId);
    if (!peer) {
      const err = new Error('Peer identity is not trusted');
      err.code = 'G_PEER_IDENTITY_UNTRUSTED';
      throw err;
    }
    if (!signature) {
      const err = new Error('Peer signature is required');
      err.code = 'G_PEER_SIGNATURE_REQUIRED';
      throw err;
    }

    const payload = this.signablePayload({ receiptHash, attestationHash, sequence, nonce });
    const ok = crypto.verify(null, Buffer.from(payload), peer.publicKeyPem, Buffer.from(signature, 'base64'));
    if (!ok) {
      const err = new Error('Peer signature verification failed');
      err.code = 'G_PEER_SIGNATURE_INVALID';
      throw err;
    }

    return Object.freeze({
      peerId,
      peerFingerprint: peer.fingerprint,
      receiptHash,
      attestationHash,
      sequence,
      nonce,
      verifiedAt: new Date().toISOString(),
    });
  }
}

module.exports = { PeerIdentityVerifier, publicKeyFingerprint, canonical };
