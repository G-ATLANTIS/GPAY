const crypto = require('crypto');
const { verifyLiveEvidenceBundle } = require('./live-evidence-bundle');

function requireNonEmpty(value, name) {
  if (typeof value !== 'string' || !value.trim()) {
    const err = new Error(`${name} is required`);
    err.code = 'EVIDENCE_SIGNING_CONFIG_MISSING';
    throw err;
  }
  return value.trim();
}

function signEvidenceBundle(bundle, { privateKeyPem, keyId } = {}) {
  if (!verifyLiveEvidenceBundle(bundle)) {
    const err = new Error('evidence bundle integrity verification failed');
    err.code = 'EVIDENCE_INTEGRITY_INVALID';
    throw err;
  }

  const pem = requireNonEmpty(privateKeyPem, 'privateKeyPem');
  const signerKeyId = requireNonEmpty(keyId, 'keyId');

  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(pem);
  } catch {
    const err = new Error('invalid evidence signing private key');
    err.code = 'EVIDENCE_SIGNING_KEY_INVALID';
    throw err;
  }

  if (privateKey.asymmetricKeyType !== 'ed25519') {
    const err = new Error('evidence signing key must be Ed25519');
    err.code = 'EVIDENCE_SIGNING_KEY_TYPE_INVALID';
    throw err;
  }

  const signature = crypto.sign(null, Buffer.from(bundle.evidenceHash, 'hex'), privateKey);

  return {
    ...bundle,
    signatureStatus: 'signed',
    signatureAlgorithm: 'Ed25519',
    signatureKeyId: signerKeyId,
    signature: signature.toString('base64'),
  };
}

function verifySignedEvidenceBundle(bundle, { publicKeyPem, expectedKeyId } = {}) {
  if (!verifyLiveEvidenceBundle(bundle)) return false;
  if (bundle?.signatureStatus !== 'signed') return false;
  if (bundle?.signatureAlgorithm !== 'Ed25519') return false;
  if (typeof bundle?.signature !== 'string' || !bundle.signature) return false;
  if (typeof bundle?.signatureKeyId !== 'string' || !bundle.signatureKeyId) return false;
  if (expectedKeyId && bundle.signatureKeyId !== expectedKeyId) return false;

  try {
    const publicKey = crypto.createPublicKey(requireNonEmpty(publicKeyPem, 'publicKeyPem'));
    if (publicKey.asymmetricKeyType !== 'ed25519') return false;
    return crypto.verify(
      null,
      Buffer.from(bundle.evidenceHash, 'hex'),
      publicKey,
      Buffer.from(bundle.signature, 'base64')
    );
  } catch {
    return false;
  }
}

function signEvidenceBundleFromEnv(bundle, env = process.env) {
  return signEvidenceBundle(bundle, {
    privateKeyPem: env.GPAY_EVIDENCE_ED25519_PRIVATE_KEY_PEM,
    keyId: env.GPAY_EVIDENCE_SIGNING_KEY_ID,
  });
}

module.exports = {
  signEvidenceBundle,
  verifySignedEvidenceBundle,
  signEvidenceBundleFromEnv,
};
