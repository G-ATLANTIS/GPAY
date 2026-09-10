const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { createLiveEvidenceBundle } = require('../backend/utils/live-evidence-bundle');
const {
  signEvidenceBundle,
  verifySignedEvidenceBundle,
  signEvidenceBundleFromEnv,
} = require('../backend/utils/evidence-signature');

function sampleEvidence() {
  return createLiveEvidenceBundle({
    provider: 'mollie',
    providerPaymentId: 'tr_sig_1',
    orderId: 'ORDER-SIG-1',
    amount: '10.00',
    currency: 'EUR',
    providerStatus: 'paid',
    providerReadbackVerified: true,
    providerReadbackAt: '2026-09-10T16:30:00.000Z',
    receiptHash: 'a'.repeat(64),
    settlementEventId: 'b'.repeat(64),
    deploymentId: 'gpay-prod-eu-1',
    deploymentCommit: 'abcdef1234567890',
    environment: 'production',
    gcoinExecutionStatus: 'not_attempted',
    gcoinTransactionHash: null,
  });
}

function keypair() {
  return crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

test('Ed25519 signature authenticates an intact evidence bundle', () => {
  const { publicKey, privateKey } = keypair();
  const signed = signEvidenceBundle(sampleEvidence(), {
    privateKeyPem: privateKey,
    keyId: 'evidence-key-test-1',
  });

  assert.equal(signed.signatureStatus, 'signed');
  assert.equal(signed.signatureAlgorithm, 'Ed25519');
  assert.equal(verifySignedEvidenceBundle(signed, {
    publicKeyPem: publicKey,
    expectedKeyId: 'evidence-key-test-1',
  }), true);
});

test('signature verification fails after evidence tampering', () => {
  const { publicKey, privateKey } = keypair();
  const signed = signEvidenceBundle(sampleEvidence(), {
    privateKeyPem: privateKey,
    keyId: 'evidence-key-test-1',
  });

  assert.equal(verifySignedEvidenceBundle({ ...signed, amount: '999.00' }, {
    publicKeyPem: publicKey,
    expectedKeyId: 'evidence-key-test-1',
  }), false);
});

test('signature verification rejects a different public key', () => {
  const signer = keypair();
  const other = keypair();
  const signed = signEvidenceBundle(sampleEvidence(), {
    privateKeyPem: signer.privateKey,
    keyId: 'evidence-key-test-1',
  });

  assert.equal(verifySignedEvidenceBundle(signed, {
    publicKeyPem: other.publicKey,
    expectedKeyId: 'evidence-key-test-1',
  }), false);
});

test('signing fails closed without runtime signing configuration', () => {
  assert.throws(
    () => signEvidenceBundleFromEnv(sampleEvidence(), {}),
    err => err && err.code === 'EVIDENCE_SIGNING_CONFIG_MISSING'
  );
});

test('signing rejects non-Ed25519 keys', () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  assert.throws(
    () => signEvidenceBundle(sampleEvidence(), {
      privateKeyPem: privateKey,
      keyId: 'wrong-key-type',
    }),
    err => err && err.code === 'EVIDENCE_SIGNING_KEY_TYPE_INVALID'
  );
});
