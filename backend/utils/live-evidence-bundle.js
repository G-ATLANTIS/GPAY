const crypto = require('crypto');

function requireString(value, name) {
  if (typeof value !== 'string' || !value.trim()) {
    const err = new Error(`${name} is required`);
    err.code = 'EVIDENCE_INVALID';
    throw err;
  }
  return value.trim();
}

function canonicalEvidencePayload(input) {
  const provider = requireString(input.provider, 'provider');
  const providerPaymentId = requireString(input.providerPaymentId, 'providerPaymentId');
  const orderId = requireString(input.orderId, 'orderId');
  const amount = requireString(String(input.amount ?? ''), 'amount');
  const currency = requireString(input.currency, 'currency');
  const providerStatus = requireString(input.providerStatus, 'providerStatus');
  const providerReadbackAt = requireString(input.providerReadbackAt, 'providerReadbackAt');
  const receiptHash = requireString(input.receiptHash, 'receiptHash');
  const settlementEventId = requireString(input.settlementEventId, 'settlementEventId');
  const deploymentId = requireString(input.deploymentId, 'deploymentId');

  if (input.providerReadbackVerified !== true) {
    const err = new Error('providerReadbackVerified must be true');
    err.code = 'EVIDENCE_UNVERIFIED_PROVIDER_STATE';
    throw err;
  }

  return JSON.stringify({
    schemaVersion: '1.0.0',
    provider,
    providerPaymentId,
    orderId,
    amount,
    currency,
    providerStatus,
    providerReadbackVerified: true,
    providerReadbackAt,
    receiptHash,
    settlementEventId,
    deploymentId,
    deploymentCommit: input.deploymentCommit || null,
    environment: input.environment || 'production',
    gcoinExecutionStatus: input.gcoinExecutionStatus || 'not_attempted',
    gcoinTransactionHash: input.gcoinTransactionHash || null,
  });
}

function createLiveEvidenceBundle(input) {
  const canonicalPayload = canonicalEvidencePayload(input);
  const evidenceHash = crypto.createHash('sha256').update(canonicalPayload).digest('hex');

  return {
    schemaVersion: '1.0.0',
    ...JSON.parse(canonicalPayload),
    evidenceHash,
    evidenceIntegrity: 'sha256-canonical-payload',
    signatureStatus: 'unsigned',
  };
}

function verifyLiveEvidenceBundle(bundle) {
  if (!bundle || typeof bundle !== 'object' || typeof bundle.evidenceHash !== 'string') return false;
  try {
    const payload = canonicalEvidencePayload(bundle);
    const expected = crypto.createHash('sha256').update(payload).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(bundle.evidenceHash, 'hex'));
  } catch {
    return false;
  }
}

module.exports = { canonicalEvidencePayload, createLiveEvidenceBundle, verifyLiveEvidenceBundle };
