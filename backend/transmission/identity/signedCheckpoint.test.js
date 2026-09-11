'use strict';

const assert = require('assert');
const crypto = require('crypto');
const { SignedCheckpointRegistry, sha256, stable } = require('./signedCheckpoint');

function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKey,
  };
}

function sign(privateKey, value) {
  return crypto.sign(null, Buffer.from(stable(value)), privateKey).toString('base64');
}

const first = keypair();
const second = keypair();
const registry = new SignedCheckpointRegistry();
const trusted = registry.trust({ peerId: 'peer-a', publicKeyPem: first.publicKeyPem });

const cp1 = { sequence: 10, receiptChainHead: 'r10', previousCheckpointHash: null };
const cp1Body = { ...cp1, peerId: 'peer-a', keyFingerprint: trusted.keyFingerprint, generation: 1 };
const committed1 = registry.verifyAndCommit({ peerId: 'peer-a', checkpoint: cp1, signature: sign(first.privateKey, cp1Body) });
assert.equal(committed1.sequence, 10);

const nextFingerprint = sha256(second.publicKeyPem);
const rotatePayload = {
  peerId: 'peer-a',
  currentKeyFingerprint: trusted.keyFingerprint,
  nextKeyFingerprint: nextFingerprint,
  nextGeneration: 2,
};
const rotated = registry.rotate({
  peerId: 'peer-a',
  newPublicKeyPem: second.publicKeyPem,
  rotationSignature: sign(first.privateKey, rotatePayload),
});
assert.equal(rotated.generation, 2);
assert.equal(rotated.previousKeyFingerprint, trusted.keyFingerprint);

const cp2 = { sequence: 20, receiptChainHead: 'r20', previousCheckpointHash: committed1.checkpointHash };
const cp2Body = { ...cp2, peerId: 'peer-a', keyFingerprint: rotated.keyFingerprint, generation: 2 };
const committed2 = registry.verifyAndCommit({ peerId: 'peer-a', checkpoint: cp2, signature: sign(second.privateKey, cp2Body) });
assert.equal(committed2.sequence, 20);

assert.throws(() => registry.verifyAndCommit({
  peerId: 'peer-a',
  checkpoint: { sequence: 30, receiptChainHead: 'r30', previousCheckpointHash: 'bad' },
  signature: sign(second.privateKey, { sequence: 30 }),
}), err => err.code === 'G_CHECKPOINT_CHAIN_BROKEN');

assert.throws(() => registry.rotate({
  peerId: 'peer-a',
  newPublicKeyPem: first.publicKeyPem,
  rotationSignature: sign(first.privateKey, rotatePayload),
}), err => err.code === 'G_KEY_ROTATION_INVALID');

registry.revoke('peer-a');
assert.throws(() => registry.verifyAndCommit({ peerId: 'peer-a', checkpoint: cp2, signature: sign(second.privateKey, cp2Body) }), err => err.code === 'G_PEER_NOT_TRUSTED');

console.log('G Ether Web signed checkpoint tests passed');
