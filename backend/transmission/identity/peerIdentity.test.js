'use strict';

const assert = require('assert');
const crypto = require('crypto');
const { PeerIdentityVerifier } = require('./peerIdentity');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });

const verifier = new PeerIdentityVerifier();
verifier.trust({ peerId: 'peer-A', publicKeyPem });

const payload = verifier.signablePayload({
  receiptHash: 'receipt-1',
  attestationHash: 'attest-1',
  sequence: 1,
  nonce: 'nonce-1',
});
const signature = crypto.sign(null, Buffer.from(payload), privateKey).toString('base64');

const verified = verifier.verify({
  peerId: 'peer-A',
  receiptHash: 'receipt-1',
  attestationHash: 'attest-1',
  sequence: 1,
  nonce: 'nonce-1',
  signature,
});
assert.equal(verified.peerId, 'peer-A');
assert.ok(verified.peerFingerprint);

assert.throws(() => verifier.verify({
  peerId: 'peer-A',
  receiptHash: 'receipt-tampered',
  attestationHash: 'attest-1',
  sequence: 1,
  nonce: 'nonce-1',
  signature,
}), (err) => err && err.code === 'G_PEER_SIGNATURE_INVALID');

verifier.revoke('peer-A');
assert.throws(() => verifier.verify({
  peerId: 'peer-A',
  receiptHash: 'receipt-1',
  attestationHash: 'attest-1',
  sequence: 1,
  nonce: 'nonce-1',
  signature,
}), (err) => err && err.code === 'G_PEER_IDENTITY_UNTRUSTED');

console.log('G Ether Web peer identity tests passed');
