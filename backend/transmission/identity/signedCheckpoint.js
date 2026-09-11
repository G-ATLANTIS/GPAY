'use strict';

const crypto = require('crypto');

function stable(value) {
  return JSON.stringify(value, Object.keys(value).sort());
}

function sha256(value) {
  return crypto.createHash('sha256').update(typeof value === 'string' ? value : stable(value)).digest('hex');
}

class SignedCheckpointRegistry {
  constructor() {
    this.peers = new Map();
    this.lastCheckpoint = new Map();
  }

  trust({ peerId, publicKeyPem }) {
    if (!peerId || !publicKeyPem) throw new Error('peerId and publicKeyPem are required');
    const keyFingerprint = sha256(publicKeyPem);
    const record = Object.freeze({ peerId, publicKeyPem, keyFingerprint, revoked: false, generation: 1 });
    this.peers.set(peerId, record);
    return record;
  }

  rotate({ peerId, newPublicKeyPem, rotationSignature }) {
    const current = this.peers.get(peerId);
    if (!current || current.revoked) {
      const err = new Error('Peer is not trusted');
      err.code = 'G_PEER_NOT_TRUSTED';
      throw err;
    }
    const nextFingerprint = sha256(newPublicKeyPem);
    const payload = Buffer.from(stable({ peerId, currentKeyFingerprint: current.keyFingerprint, nextKeyFingerprint: nextFingerprint, nextGeneration: current.generation + 1 }));
    const ok = crypto.verify(null, payload, current.publicKeyPem, Buffer.from(rotationSignature, 'base64'));
    if (!ok) {
      const err = new Error('Invalid key rotation signature');
      err.code = 'G_KEY_ROTATION_INVALID';
      throw err;
    }
    const next = Object.freeze({ peerId, publicKeyPem: newPublicKeyPem, keyFingerprint: nextFingerprint, revoked: false, generation: current.generation + 1, previousKeyFingerprint: current.keyFingerprint });
    this.peers.set(peerId, next);
    return next;
  }

  revoke(peerId) {
    const current = this.peers.get(peerId);
    if (!current) return false;
    this.peers.set(peerId, Object.freeze({ ...current, revoked: true }));
    return true;
  }

  verifyAndCommit({ peerId, checkpoint, signature }) {
    const peer = this.peers.get(peerId);
    if (!peer || peer.revoked) {
      const err = new Error('Peer is not trusted');
      err.code = 'G_PEER_NOT_TRUSTED';
      throw err;
    }
    const previous = this.lastCheckpoint.get(peerId) || null;
    const expectedPrev = previous ? previous.checkpointHash : null;
    if ((checkpoint.previousCheckpointHash || null) !== expectedPrev) {
      const err = new Error('Checkpoint continuity failure');
      err.code = 'G_CHECKPOINT_CHAIN_BROKEN';
      throw err;
    }
    const body = { ...checkpoint, peerId, keyFingerprint: peer.keyFingerprint, generation: peer.generation };
    const bytes = Buffer.from(stable(body));
    const ok = crypto.verify(null, bytes, peer.publicKeyPem, Buffer.from(signature, 'base64'));
    if (!ok) {
      const err = new Error('Checkpoint signature invalid');
      err.code = 'G_CHECKPOINT_SIGNATURE_INVALID';
      throw err;
    }
    const committed = Object.freeze({ ...body, checkpointHash: sha256(body) });
    this.lastCheckpoint.set(peerId, committed);
    return committed;
  }
}

module.exports = { SignedCheckpointRegistry, sha256, stable };
