const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createLiveEvidenceBundle,
  verifyLiveEvidenceBundle,
} = require('../backend/utils/live-evidence-bundle');

function sample(overrides = {}) {
  return {
    provider: 'mollie',
    providerPaymentId: 'tr_live_example',
    orderId: 'ORDER-LIVE-1',
    amount: '10.00',
    currency: 'EUR',
    providerStatus: 'paid',
    providerReadbackVerified: true,
    providerReadbackAt: '2026-09-10T16:00:00.000Z',
    receiptHash: 'a'.repeat(64),
    settlementEventId: 'b'.repeat(64),
    deploymentId: 'gpay-prod-eu-1',
    deploymentCommit: 'abcdef1234567890',
    environment: 'production',
    gcoinExecutionStatus: 'not_attempted',
    gcoinTransactionHash: null,
    ...overrides,
  };
}

test('live evidence bundle is deterministic for the same verified evidence', () => {
  const a = createLiveEvidenceBundle(sample());
  const b = createLiveEvidenceBundle(sample());
  assert.equal(a.evidenceHash, b.evidenceHash);
  assert.equal(a.signatureStatus, 'unsigned');
  assert.equal(verifyLiveEvidenceBundle(a), true);
});

test('tampering with verified evidence invalidates the bundle', () => {
  const bundle = createLiveEvidenceBundle(sample());
  const tampered = { ...bundle, amount: '999.00' };
  assert.equal(verifyLiveEvidenceBundle(tampered), false);
});

test('evidence creation fails closed without verified provider readback', () => {
  assert.throws(
    () => createLiveEvidenceBundle(sample({ providerReadbackVerified: false })),
    err => err && err.code === 'EVIDENCE_UNVERIFIED_PROVIDER_STATE'
  );
});

test('evidence creation fails closed when deployment provenance is missing', () => {
  assert.throws(
    () => createLiveEvidenceBundle(sample({ deploymentId: '' })),
    err => err && err.code === 'EVIDENCE_INVALID'
  );
});
