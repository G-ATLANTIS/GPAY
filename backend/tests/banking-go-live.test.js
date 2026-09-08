const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  validateProviderReadinessArtifact,
  validateSandboxPaymentArtifacts,
  validateReconciliationArtifact,
  detectRealWebhook,
  secretRotationState,
  productionConfigState,
  isolatedBankingTestEnv,
  classify
} = require('../../scripts/banking-go-live');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-go-live-test-'));
const smokeDir = path.join(tempRoot, 'smoke');
const webhookBase = path.join(tempRoot, 'webhooks');
fs.mkdirSync(smokeDir, { recursive: true });
fs.mkdirSync(path.join(webhookBase, 'sandbox'), { recursive: true });

const envSnapshot = { ...process.env };

function canonicalEvidence(record) {
  return JSON.stringify({
    version: record.version,
    type: record.type,
    provider: record.provider,
    observed_at: record.observed_at,
    evidence_ref: record.evidence_ref,
    artifact_sha256: record.artifact_sha256 ?? null
  });
}

function writeEvidence(file, type, provider, ref, artifactSha256 = null) {
  const record = {
    version: 1,
    type,
    provider,
    observed_at: new Date().toISOString(),
    evidence_ref: ref,
    artifact_sha256: artifactSha256
  };
  record.record_sha256 = crypto.createHash('sha256').update(canonicalEvidence(record)).digest('hex');
  fs.writeFileSync(file, JSON.stringify(record, null, 2) + '\n');
  return record;
}

function canonicalWebhook(record) {
  return JSON.stringify({
    version: record.version,
    provider: record.provider,
    environment: record.environment,
    event_id: record.event_id,
    event_type: record.event_type,
    event_version: record.event_version,
    payment_id: record.payment_id,
    webhook_timestamp: record.webhook_timestamp,
    signature_kid: record.signature_kid,
    signature_jku: record.signature_jku,
    raw_body_sha256: record.raw_body_sha256,
    observed_at: record.observed_at
  });
}

function stage(name, state) {
  return { name, state, detail: '' };
}

try {

  // Real runtime secrets must never influence the local deterministic test subprocesses.
  process.env.TRUELAYER_CLIENT_ID = 'real-runtime-client';
  process.env.TRUELAYER_CLIENT_SECRET = 'real-runtime-secret';
  process.env.TRUELAYER_SIGNING_KID = 'real-runtime-kid';
  process.env.TRUELAYER_PRIVATE_KEY_B64 = 'real-runtime-private-key';
  process.env.G_BANK_OPERATOR_SECRET = 'real-runtime-operator-secret';
  process.env.G_BANK_PROVIDER_PROBE_SECRET = 'real-runtime-probe-secret';
  process.env.G_BANK_ENABLE_PROVIDER_PROBE = 'true';
  const isolated = isolatedBankingTestEnv();
  assert.equal('TRUELAYER_CLIENT_ID' in isolated, false);
  assert.equal('TRUELAYER_CLIENT_SECRET' in isolated, false);
  assert.equal('TRUELAYER_SIGNING_KID' in isolated, false);
  assert.equal('TRUELAYER_PRIVATE_KEY_B64' in isolated, false);
  assert.equal('G_BANK_OPERATOR_SECRET' in isolated, false);
  assert.equal('G_BANK_PROVIDER_PROBE_SECRET' in isolated, false);
  assert.equal('G_BANK_ENABLE_PROVIDER_PROBE' in isolated, false);
  assert.equal(isolated.NODE_ENV, 'test');
  console.log('runtime secrets are stripped from local test subprocesses');

  const providerArtifact = path.join(smokeDir, 'provider-readiness-2026-09-08T00-00-00-000Z.json');
  fs.writeFileSync(providerArtifact, JSON.stringify({
    provider: 'truelayer',
    environment: 'sandbox',
    access_token_obtained: true,
    request_signature_accepted: true,
    provider_http_status: 204,
    payment_created: false,
    value_moved: false,
    verified_value_flow: false
  }));
  assert.equal(validateProviderReadinessArtifact(smokeDir).verified, true);

  const paymentId = '11111111-1111-4111-8111-111111111111';
  const paymentArtifact = path.join(smokeDir, `payment-created-${paymentId}-2026-09-08T00-00-01-000Z.json`);
  fs.writeFileSync(paymentArtifact, JSON.stringify({
    provider: 'truelayer',
    environment: 'sandbox',
    payment_id: paymentId,
    status: 'authorization_required',
    authorization_required: true,
    authorization_url_sha256: 'a'.repeat(64),
    verified_value_flow: false
  }));
  const payment = validateSandboxPaymentArtifacts(smokeDir);
  assert.equal(payment.verified, true);
  assert.equal(payment.paymentId, paymentId);

  const reconcileArtifact = path.join(smokeDir, `payment-reconcile-${paymentId}-2026-09-08T00-00-02-000Z.json`);
  fs.writeFileSync(reconcileArtifact, JSON.stringify({
    provider: 'truelayer',
    environment: 'sandbox',
    payment_id: paymentId,
    reconciliation: { state: 'BANK_ACCEPTED_NOT_SETTLEMENT_PROVEN' },
    creditor_settlement_proven: false,
    verified_value_flow: false
  }));
  assert.equal(validateReconciliationArtifact(smokeDir, paymentId).verified, true);

  process.env.G_BANK_WEBHOOK_RECEIPT_DIR = webhookBase;
  const webhook = {
    version: 1,
    provider: 'truelayer',
    environment: 'sandbox',
    event_id: '22222222-2222-4222-8222-222222222222',
    event_type: 'payment_executed',
    event_version: 1,
    payment_id: paymentId,
    webhook_timestamp: new Date().toISOString(),
    signature_kid: 'sandbox-signing-kid',
    signature_jku: 'https://webhooks.truelayer-sandbox.com/.well-known/jwks',
    raw_body_sha256: 'b'.repeat(64),
    observed_at: new Date().toISOString()
  };
  webhook.receipt_sha256 = crypto.createHash('sha256').update(canonicalWebhook(webhook)).digest('hex');
  const webhookFile = path.join(webhookBase, 'sandbox', `${webhook.event_id}.json`);
  fs.writeFileSync(webhookFile, JSON.stringify(webhook, null, 2) + '\n');
  assert.equal(detectRealWebhook(paymentId).verified, true);

  const tampered = { ...webhook, event_type: 'payment_failed' };
  fs.writeFileSync(webhookFile, JSON.stringify(tampered, null, 2) + '\n');
  assert.equal(detectRealWebhook(paymentId).verified, false);

  const rotationFile = path.join(tempRoot, 'secret-rotation.json');
  const sandboxFile = path.join(tempRoot, 'sandbox-verification.json');
  writeEvidence(rotationFile, 'SECRET_ROTATION', 'mollie', 'ROTATION-EVIDENCE-123');
  writeEvidence(
    sandboxFile,
    'SANDBOX_VERIFICATION',
    'truelayer',
    'SANDBOX-EVIDENCE-123',
    'c'.repeat(64)
  );

  process.env.G_BANK_SECRET_ROTATION_RECEIPT_FILE = rotationFile;
  process.env.G_BANK_SANDBOX_VERIFICATION_RECEIPT_FILE = sandboxFile;
  assert.equal(secretRotationState().verified, true);

  process.env.TRUELAYER_ENV = 'live';
  process.env.G_BANK_ENABLE_LIVE = 'true';
  process.env.TRUELAYER_CLIENT_ID = 'live-client';
  process.env.TRUELAYER_CLIENT_SECRET = 'live-secret';
  process.env.TRUELAYER_SIGNING_KID = 'live-kid';
  process.env.TRUELAYER_PRIVATE_KEY_PEM = 'present-for-presence-gate';
  process.env.G_BANK_APPROVAL_SECRET = 'approval-secret-012345678901234567890123456789';
  process.env.G_BANK_ALLOWED_BENEFICIARY_IBANS = 'NL91ABNA0417164300';
  process.env.G_BANK_PAYMENT_INTENT_DIR = path.join(tempRoot, 'intents');
  process.env.G_BANK_WEBHOOK_RECEIPT_DIR = webhookBase;
  assert.equal(productionConfigState().verified, true);

  assert.equal(classify([
    stage('LOCAL_TESTS', 'BLOCKED')
  ]), 'BLOCKED_LOCAL');

  assert.equal(classify([
    stage('LOCAL_TESTS', 'VERIFIED'),
    stage('PROVIDER_READINESS', 'PENDING')
  ]), 'READY_FOR_SANDBOX_PROBE');

  assert.equal(classify([
    stage('LOCAL_TESTS', 'VERIFIED'),
    stage('PROVIDER_READINESS', 'VERIFIED'),
    stage('SANDBOX_PAYMENT', 'PENDING'),
    stage('SANDBOX_RECONCILIATION', 'PENDING')
  ]), 'SANDBOX_PROVIDER_VERIFIED');

  assert.equal(classify([
    stage('LOCAL_TESTS', 'VERIFIED'),
    stage('PROVIDER_READINESS', 'VERIFIED'),
    stage('SANDBOX_PAYMENT', 'VERIFIED'),
    stage('SANDBOX_RECONCILIATION', 'VERIFIED'),
    stage('REAL_WEBHOOK', 'PENDING')
  ]), 'SANDBOX_E2E_PARTIAL');

  assert.equal(classify([
    stage('LOCAL_TESTS', 'VERIFIED'),
    stage('PROVIDER_READINESS', 'VERIFIED'),
    stage('SANDBOX_PAYMENT', 'VERIFIED'),
    stage('SANDBOX_RECONCILIATION', 'VERIFIED'),
    stage('REAL_WEBHOOK', 'VERIFIED'),
    stage('SECRET_ROTATION', 'BLOCKED')
  ]), 'SANDBOX_E2E_VERIFIED_SECURITY_BLOCKED');

  assert.equal(classify([
    stage('LOCAL_TESTS', 'VERIFIED'),
    stage('PROVIDER_READINESS', 'VERIFIED'),
    stage('SANDBOX_PAYMENT', 'VERIFIED'),
    stage('SANDBOX_RECONCILIATION', 'VERIFIED'),
    stage('REAL_WEBHOOK', 'VERIFIED'),
    stage('SECRET_ROTATION', 'VERIFIED'),
    stage('PRODUCTION_CONFIG', 'PENDING')
  ]), 'READY_FOR_PRODUCTION_ONBOARDING');

  assert.equal(classify([
    stage('LOCAL_TESTS', 'VERIFIED'),
    stage('PROVIDER_READINESS', 'VERIFIED'),
    stage('SANDBOX_PAYMENT', 'VERIFIED'),
    stage('SANDBOX_RECONCILIATION', 'VERIFIED'),
    stage('REAL_WEBHOOK', 'VERIFIED'),
    stage('SECRET_ROTATION', 'VERIFIED'),
    stage('PRODUCTION_CONFIG', 'VERIFIED'),
    stage('ENV_READINESS', 'PENDING')
  ]), 'PRODUCTION_CONFIG_BLOCKED');

  assert.equal(classify([
    stage('LOCAL_TESTS', 'VERIFIED'),
    stage('PROVIDER_READINESS', 'VERIFIED'),
    stage('SANDBOX_PAYMENT', 'VERIFIED'),
    stage('SANDBOX_RECONCILIATION', 'VERIFIED'),
    stage('REAL_WEBHOOK', 'VERIFIED'),
    stage('SECRET_ROTATION', 'VERIFIED'),
    stage('PRODUCTION_CONFIG', 'VERIFIED'),
    stage('ENV_READINESS', 'VERIFIED')
  ]), 'READY_FOR_LIVE_CANARY');

  console.log('G-Bank go-live orchestrator tests: PASS');
} finally {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  for (const [key, value] of Object.entries(envSnapshot)) {
    process.env[key] = value;
  }
  fs.rmSync(tempRoot, { recursive: true, force: true });
}
