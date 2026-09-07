const assert = require('node:assert/strict');
const crypto = require('node:crypto');

process.env.TRUELAYER_ENV = 'sandbox';
process.env.G_BANK_MAX_PAYMENT_EUR = '100';
process.env.G_BANK_ENABLE_LIVE = 'false';

const router = require('../routes/openbanking');
const {
  providerConfigStatus,
  assertProviderProbeEnabled,
  isValidIban,
  approvalMessage,
  assertPaymentInput,
  assertLiveApproval,
  buildTrueLayerSigningPayload,
  signRequest,
  performProviderReadiness,
  executionGraphStatus,
  validateEvidenceReceipt,
  evidenceStatus,
  expectedWebhookJku,
  parseDetachedTlSignature,
  validateWebhookTimestamp,
  buildWebhookSigningPayload,
  verifyWebhookSignature,
  fetchWebhookJwks,
  observeWebhookEvent,
  verifyAndClassifyWebhook
} = router._test;

function mustThrow(fn, pattern) {
  let error;
  try {
    fn();
  } catch (err) {
    error = err;
  }
  assert.ok(error, 'expected function to throw');
  if (pattern) assert.match(String(error.message), pattern);
}

assert.equal(isValidIban('NL91 ABNA 0417 1643 00'), true);
assert.equal(isValidIban('NL91 ABNA 0417 1643 01'), false);
assert.equal(isValidIban('not-an-iban'), false);


// Provider readiness probe is explicit opt-in and does not imply payment authority.
process.env.TRUELAYER_ENV = 'sandbox';
process.env.G_BANK_ENABLE_PROVIDER_PROBE = 'false';
process.env.G_BANK_PROVIDER_PROBE_SECRET = 'probe-secret-012345678901234567890123';
mustThrow(() => assertProviderProbeEnabled(process.env.G_BANK_PROVIDER_PROBE_SECRET), /disabled/);
assert.equal(providerConfigStatus().provider_probe_enabled, false);

process.env.G_BANK_ENABLE_PROVIDER_PROBE = 'true';
assert.doesNotThrow(() => assertProviderProbeEnabled(process.env.G_BANK_PROVIDER_PROBE_SECRET));
mustThrow(() => assertProviderProbeEnabled('wrong-probe-secret'), /authorization failed/);
assert.equal(providerConfigStatus().provider_probe_enabled, true);

const parsed = assertPaymentInput({
  amount_eur: '12.34',
  beneficiary: {
    name: 'Test Merchant',
    iban: 'NL91ABNA0417164300',
    reference: 'TEST-123'
  },
  user: {
    name: 'Test User',
    email: 'test@example.invalid',
    phone: '+31600000000',
    date_of_birth: '1990-01-01',
    address: {
      address_line1: 'Teststraat 1',
      city: 'Amsterdam',
      zip: '1000AA',
      country_code: 'NL'
    }
  }
});

assert.equal(parsed.amountInMinor, 1234);
assert.equal(parsed.amountEur, 12.34);
assert.equal(parsed.beneficiary.iban, 'NL91ABNA0417164300');

mustThrow(() => assertPaymentInput({
  ...{
    amount_eur: '100.01',
    beneficiary: {
      name: 'Test Merchant',
      iban: 'NL91ABNA0417164300',
      reference: 'TEST-123'
    },
    user: {
      name: 'Test User',
      email: 'test@example.invalid',
      phone: '+31600000000',
      date_of_birth: '1990-01-01',
      address: {
        address_line1: 'Teststraat 1',
        city: 'Amsterdam',
        zip: '1000AA',
        country_code: 'NL'
      }
    }
  }
}), /exceeds/);

mustThrow(() => assertPaymentInput({
  amount_eur: '12.34',
  beneficiary: {
    name: 'Test Merchant',
    iban: 'NL91ABNA0417164301',
    reference: 'TEST-123'
  },
  user: {
    name: 'Test User',
    email: 'test@example.invalid',
    phone: '+31600000000',
    date_of_birth: '1990-01-01',
    address: {
      address_line1: 'Teststraat 1',
      city: 'Amsterdam',
      zip: '1000AA',
      country_code: 'NL'
    }
  }
}), /checksum/);

// Live approval is bound to exact intent parameters.
process.env.TRUELAYER_ENV = 'live';
process.env.G_BANK_ENABLE_LIVE = 'true';
process.env.G_BANK_MAX_PAYMENT_EUR = '100';
process.env.G_BANK_APPROVAL_SECRET = 'unit-test-secret';
process.env.G_BANK_ALLOWED_BENEFICIARY_IBANS = 'NL91ABNA0417164300';

// Synthetic release evidence for the live approval unit test.
const approvalEvidenceFs = require('node:fs');
const approvalEvidenceOs = require('node:os');
const approvalEvidencePath = require('node:path');
const approvalEvidenceDir = approvalEvidenceFs.mkdtempSync(approvalEvidencePath.join(approvalEvidenceOs.tmpdir(), 'g-bank-live-approval-evidence-'));

function writeSyntheticEvidence(filename, type, provider, evidenceRef, artifactSha256 = null) {
  const record = {
    version: 1,
    type,
    provider,
    observed_at: new Date().toISOString(),
    evidence_ref: evidenceRef,
    artifact_sha256: artifactSha256
  };
  const canonical = JSON.stringify({
    version: record.version,
    type: record.type,
    provider: record.provider,
    observed_at: record.observed_at,
    evidence_ref: record.evidence_ref,
    artifact_sha256: record.artifact_sha256
  });
  record.record_sha256 = crypto.createHash('sha256').update(canonical).digest('hex');
  const target = approvalEvidencePath.join(approvalEvidenceDir, filename);
  approvalEvidenceFs.writeFileSync(target, JSON.stringify(record, null, 2) + '\n');
  return target;
}

process.env.G_BANK_SECRET_ROTATION_RECEIPT_FILE = writeSyntheticEvidence(
  'secret-rotation.json',
  'SECRET_ROTATION',
  'mollie',
  'UNIT-TEST-ROTATION'
);
process.env.G_BANK_SANDBOX_VERIFICATION_RECEIPT_FILE = writeSyntheticEvidence(
  'sandbox-verification.json',
  'SANDBOX_VERIFICATION',
  'truelayer',
  'UNIT-TEST-SANDBOX',
  crypto.createHash('sha256').update('synthetic-sandbox-artifact').digest('hex')
);

process.env.TRUELAYER_CLIENT_ID = 'test-client';
process.env.TRUELAYER_CLIENT_SECRET = 'test-secret';
process.env.TRUELAYER_SIGNING_KID = 'test-kid';
process.env.TRUELAYER_PRIVATE_KEY_PEM = 'test-key';
process.env.TRUELAYER_RETURN_URI = 'https://example.invalid/return';

const intent = {
  idempotencyKey: '11111111-1111-4111-8111-111111111111',
  amountInMinor: 1234,
  iban: 'NL91ABNA0417164300',
  reference: 'TEST-123'
};

const approval = crypto
  .createHmac('sha256', process.env.G_BANK_APPROVAL_SECRET)
  .update(approvalMessage(intent))
  .digest('hex');

assert.doesNotThrow(() => assertLiveApproval({
  ...intent,
  approvalHeader: approval
}));

mustThrow(() => assertLiveApproval({
  ...intent,
  amountInMinor: 1235,
  approvalHeader: approval
}), /did not match/);

mustThrow(() => assertLiveApproval({
  ...intent,
  iban: 'NL02RABO0123456789',
  approvalHeader: approval
}), /allowlist/);

approvalEvidenceFs.rmSync(approvalEvidenceDir, { recursive: true, force: true });
delete process.env.G_BANK_SECRET_ROTATION_RECEIPT_FILE;
delete process.env.G_BANK_SANDBOX_VERIFICATION_RECEIPT_FILE;

console.log('Open Banking policy tests: PASS');


// Request-signing v2: verify detached ES512 JWS locally with a generated P-521 key.
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp521r1' });
process.env.TRUELAYER_PRIVATE_KEY_PEM = privateKey.export({ type: 'pkcs8', format: 'pem' });
process.env.TRUELAYER_SIGNING_KID = '11111111-2222-4333-8444-555555555555';

const signingBody = JSON.stringify({ amount_in_minor: 1234, currency: 'EUR' });
const signingIdempotencyKey = '22222222-2222-4222-8222-222222222222';
const signingPath = '/v3/payments';
const detached = signRequest({
  method: 'POST',
  path: signingPath,
  body: signingBody,
  idempotencyKey: signingIdempotencyKey
});

const [protectedHeader, emptyPayload, encodedSignature] = detached.split('.');
assert.equal(emptyPayload, '');

const parsedHeader = JSON.parse(Buffer.from(protectedHeader, 'base64url').toString('utf8'));
assert.deepEqual(parsedHeader, {
  alg: 'ES512',
  kid: process.env.TRUELAYER_SIGNING_KID,
  tl_version: '2',
  tl_headers: 'Idempotency-Key'
});

const signingPayload = buildTrueLayerSigningPayload({
  method: 'POST',
  path: signingPath,
  headers: { 'Idempotency-Key': signingIdempotencyKey },
  body: signingBody
});
const encodedSigningPayload = Buffer.from(signingPayload).toString('base64url');
const signingInput = `${protectedHeader}.${encodedSigningPayload}`;
const rawSignature = Buffer.from(encodedSignature, 'base64url');

assert.equal(rawSignature.length, 132);
assert.equal(
  crypto.verify('sha512', Buffer.from(signingInput, 'utf8'), {
    key: publicKey,
    dsaEncoding: 'ieee-p1363'
  }, rawSignature),
  true
);

mustThrow(() => {
  process.env.TRUELAYER_PRIVATE_KEY_PEM = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  signRequest({
    method: 'POST',
    path: signingPath,
    body: signingBody,
    idempotencyKey: signingIdempotencyKey
  });
}, /P-521/);

console.log('TrueLayer request-signing tests: PASS');


// Key bootstrap creates an ignored local P-521 keypair with restrictive private-key permissions.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const keygenDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-keygen-'));
const keygenRun = spawnSync(process.execPath, [
  path.join(__dirname, '..', '..', 'scripts', 'generate-truelayer-keypair.js'),
  '--out-dir',
  keygenDir
], { encoding: 'utf8' });

assert.equal(keygenRun.status, 0, keygenRun.stderr || keygenRun.stdout);

const generatedPrivatePath = path.join(keygenDir, 'ec512-private-key.pem');
const generatedPublicPath = path.join(keygenDir, 'ec512-public-key.pem');
assert.equal(fs.existsSync(generatedPrivatePath), true);
assert.equal(fs.existsSync(generatedPublicPath), true);

const generatedPrivateKey = crypto.createPrivateKey(fs.readFileSync(generatedPrivatePath, 'utf8'));
assert.equal(generatedPrivateKey.asymmetricKeyType, 'ec');
assert.equal(generatedPrivateKey.asymmetricKeyDetails?.namedCurve, 'secp521r1');

if (process.platform !== 'win32') {
  assert.equal(fs.statSync(generatedPrivatePath).mode & 0o777, 0o600);
}

const overwriteRun = spawnSync(process.execPath, [
  path.join(__dirname, '..', '..', 'scripts', 'generate-truelayer-keypair.js'),
  '--out-dir',
  keygenDir
], { encoding: 'utf8' });
assert.equal(overwriteRun.status, 2);

fs.rmSync(keygenDir, { recursive: true, force: true });
console.log('TrueLayer key-bootstrap tests: PASS');


// Banking readiness CLI fails closed with missing credentials and accepts a valid synthetic P-521 config.
const readinessScript = path.join(__dirname, '..', '..', 'scripts', 'check-banking-readiness.js');
const readinessBlocked = spawnSync(process.execPath, [readinessScript], {
  encoding: 'utf8',
  env: {
    ...process.env,
    TRUELAYER_ENV: 'sandbox',
    TRUELAYER_CLIENT_ID: '',
    TRUELAYER_CLIENT_SECRET: '',
    TRUELAYER_SIGNING_KID: '',
    TRUELAYER_PRIVATE_KEY_PEM: '',
    TRUELAYER_PRIVATE_KEY_B64: '',
    TRUELAYER_RETURN_URI: '',
    G_BANK_MAX_PAYMENT_EUR: '100',
    G_BANK_ENABLE_LIVE: 'false',
    G_BANK_ENABLE_PROVIDER_PROBE: 'false'
  }
});
assert.equal(readinessBlocked.status, 2);
assert.match(readinessBlocked.stderr, /BLOCKED/);

const syntheticPair = crypto.generateKeyPairSync('ec', { namedCurve: 'secp521r1' });
const syntheticPem = syntheticPair.privateKey.export({ type: 'pkcs8', format: 'pem' });
const readinessConfigured = spawnSync(process.execPath, [readinessScript], {
  encoding: 'utf8',
  env: {
    ...process.env,
    TRUELAYER_ENV: 'sandbox',
    TRUELAYER_CLIENT_ID: 'synthetic-client',
    TRUELAYER_CLIENT_SECRET: 'synthetic-secret',
    TRUELAYER_SIGNING_KID: 'synthetic-kid',
    TRUELAYER_PRIVATE_KEY_PEM: syntheticPem,
    TRUELAYER_PRIVATE_KEY_B64: '',
    TRUELAYER_RETURN_URI: 'http://localhost:5173/bank-return',
    G_BANK_MAX_PAYMENT_EUR: '100',
    G_BANK_ENABLE_LIVE: 'false',
    G_BANK_ENABLE_PROVIDER_PROBE: 'false'
  }
});
assert.equal(readinessConfigured.status, 0, readinessConfigured.stderr || readinessConfigured.stdout);
assert.match(readinessConfigured.stdout, /CONFIGURED/);
assert.match(readinessConfigured.stdout, /No payment was created/);

console.log('Banking readiness CLI tests: PASS');

// Approval CLI requires explicit confirmation, allowlist, max limit and writes a mode-0600 token file.
const approvalScript = path.join(__dirname, '..', '..', 'scripts', 'generate-g-bank-approval.js');
const approvalRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-approval-'));
const approvalEnv = {
  ...process.env,
  G_BANK_APPROVAL_SECRET: '0123456789012345678901234567890123456789',
  G_BANK_ALLOWED_BENEFICIARY_IBANS: 'NL91ABNA0417164300',
  G_BANK_MAX_PAYMENT_EUR: '100'
};
const approvalArgs = [
  approvalScript,
  '--confirm-approval',
  '--idempotency-key', '33333333-3333-4333-8333-333333333333',
  '--amount-eur', '12.34',
  '--iban', 'NL91ABNA0417164300',
  '--reference', 'TEST-APPROVAL'
];

const approvalRun = spawnSync(process.execPath, approvalArgs, {
  encoding: 'utf8',
  cwd: approvalRoot,
  env: approvalEnv
});
assert.equal(approvalRun.status, 0, approvalRun.stderr || approvalRun.stdout);
const approvalPath = path.join(approvalRoot, '.secrets', 'approvals', '33333333-3333-4333-8333-333333333333.approval');
assert.equal(fs.existsSync(approvalPath), true);
assert.match(fs.readFileSync(approvalPath, 'utf8').trim(), /^[0-9a-f]{64}$/);
if (process.platform !== 'win32') assert.equal(fs.statSync(approvalPath).mode & 0o777, 0o600);

const noConfirm = spawnSync(process.execPath, approvalArgs.filter(x => x !== '--confirm-approval'), {
  encoding: 'utf8',
  cwd: approvalRoot,
  env: approvalEnv
});
assert.equal(noConfirm.status, 2);

fs.rmSync(approvalRoot, { recursive: true, force: true });
console.log('G-Bank approval CLI tests: PASS');


// Provider readiness HTTP contract: only token + /test-signature are allowed.
(async () => {
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'secp521r1' });
  process.env.TRUELAYER_ENV = 'sandbox';
  process.env.G_BANK_ENABLE_PROVIDER_PROBE = 'true';
  process.env.G_BANK_PROVIDER_PROBE_SECRET = 'contract-probe-secret-012345678901234567890';
  process.env.TRUELAYER_CLIENT_ID = 'contract-client';
  process.env.TRUELAYER_CLIENT_SECRET = 'contract-secret';
  process.env.TRUELAYER_SIGNING_KID = 'contract-kid';
  process.env.TRUELAYER_PRIVATE_KEY_PEM = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  process.env.TRUELAYER_PRIVATE_KEY_B64 = '';

  const calls = [];
  const fakeHttp = {
    async post(url, body, options) {
      calls.push({ url, body, options });
      if (url === 'https://auth.truelayer-sandbox.com/connect/token') {
        return { status: 200, data: { access_token: 'synthetic-access-token' } };
      }
      if (url === 'https://api.truelayer-sandbox.com/test-signature') {
        assert.equal(options.headers.Authorization, 'Bearer synthetic-access-token');
        assert.match(options.headers['Tl-Signature'], /^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$/);
        assert.match(options.headers['Idempotency-Key'], /^[0-9a-f-]{36}$/i);
        assert.match(body, /^\{"nonce":"[0-9a-f-]{36}"\}$/i);
        return { status: 204, data: null };
      }
      throw new Error(`Unexpected HTTP target in provider readiness: ${url}`);
    }
  };

  const result = await performProviderReadiness(fakeHttp, process.env.G_BANK_PROVIDER_PROBE_SECRET);
  assert.equal(result.request_signature_accepted, true);
  assert.equal(result.provider_http_status, 204);
  assert.equal(result.payment_created, false);
  assert.equal(result.bank_authorization_started, false);
  assert.equal(result.value_moved, false);
  assert.equal(result.verified_write, false);
  assert.equal(result.verified_value_flow, false);

  assert.deepEqual(calls.map(call => call.url), [
    'https://auth.truelayer-sandbox.com/connect/token',
    'https://api.truelayer-sandbox.com/test-signature'
  ]);
  assert.equal(calls.some(call => call.url.includes('/v3/payments')), false);

  console.log('Provider readiness HTTP contract tests: PASS');
})().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});


// Live mode requires valid evidence receipt files in addition to credentials and approval controls.
process.env.TRUELAYER_ENV = 'live';
process.env.G_BANK_ENABLE_LIVE = 'true';
process.env.G_BANK_APPROVAL_SECRET = 'unit-test-approval-secret-012345678901234567890';
process.env.G_BANK_ALLOWED_BENEFICIARY_IBANS = 'NL91ABNA0417164300';
delete process.env.G_BANK_SECRET_ROTATION_RECEIPT_FILE;
delete process.env.G_BANK_SANDBOX_VERIFICATION_RECEIPT_FILE;

let liveStatus = router._test.configStatus();
assert.equal(liveStatus.configured, false);
assert.equal(liveStatus.missing.includes('G_BANK_SECRET_ROTATION_RECEIPT_FILE(valid)'), true);
assert.equal(liveStatus.missing.includes('G_BANK_SANDBOX_VERIFICATION_RECEIPT_FILE(valid,fresh)'), true);
assert.equal(liveStatus.historical_secret_rotation_receipt_present, false);
assert.equal(liveStatus.sandbox_verification_receipt_present, false);

console.log('Live evidence receipt gate tests: PASS');


// Execution graph status never promotes payment/value edges from local configuration alone.
process.env.TRUELAYER_ENV = 'sandbox';
process.env.G_BANK_ENABLE_LIVE = 'false';
process.env.G_BANK_ENABLE_PROVIDER_PROBE = 'false';
const graphStatus = executionGraphStatus();
assert.equal(graphStatus.edges.provider_authentication.active, false);
assert.equal(graphStatus.edges.payment_creation.active, false);
assert.equal(graphStatus.edges.value_flow.active, false);
assert.equal(graphStatus.verified_value_flow, false);
assert.equal(graphStatus.edges.value_flow.class, 'VERIFIED_VALUE_FLOW');
console.log('Execution graph status tests: PASS');


// Banking evidence records are integrity-checked and freshness-bound.
const evidenceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-evidence-'));
const evidenceScript = path.join(__dirname, '..', '..', 'scripts', 'record-banking-evidence.js');

const rotationArtifact = path.join(evidenceRoot, 'rotation-proof.txt');
fs.writeFileSync(rotationArtifact, 'provider-side rotation confirmation test artifact\n');

const sandboxArtifact = path.join(evidenceRoot, 'sandbox-readiness.json');
fs.writeFileSync(sandboxArtifact, JSON.stringify({
  request_signature_accepted: true,
  provider_http_status: 204,
  payment_created: false,
  value_moved: false
}));

const rotationRun = spawnSync(process.execPath, [
  evidenceScript,
  '--confirm-evidence',
  '--type', 'SECRET_ROTATION',
  '--provider', 'mollie',
  '--evidence-ref', 'TEST-ROTATION-TICKET-123',
  '--artifact', rotationArtifact
], { encoding: 'utf8', cwd: evidenceRoot });
assert.equal(rotationRun.status, 0, rotationRun.stderr || rotationRun.stdout);

const sandboxRun = spawnSync(process.execPath, [
  evidenceScript,
  '--confirm-evidence',
  '--type', 'SANDBOX_VERIFICATION',
  '--provider', 'truelayer',
  '--evidence-ref', 'TEST-SANDBOX-204-123',
  '--artifact', sandboxArtifact
], { encoding: 'utf8', cwd: evidenceRoot });
assert.equal(sandboxRun.status, 0, sandboxRun.stderr || sandboxRun.stdout);

const rotationReceipt = path.join(evidenceRoot, '.secrets', 'evidence', 'secret-rotation.json');
const sandboxReceipt = path.join(evidenceRoot, '.secrets', 'evidence', 'sandbox-verification.json');

assert.equal(validateEvidenceReceipt(rotationReceipt, 'SECRET_ROTATION', 10 * 365 * 24 * 60 * 60 * 1000).valid, true);
assert.equal(validateEvidenceReceipt(sandboxReceipt, 'SANDBOX_VERIFICATION', 30 * 24 * 60 * 60 * 1000).valid, true);

// Tampering must invalidate the record.
const tampered = JSON.parse(fs.readFileSync(sandboxReceipt, 'utf8'));
tampered.evidence_ref = 'TAMPERED-REFERENCE';
fs.writeFileSync(sandboxReceipt, JSON.stringify(tampered, null, 2) + '\n');
assert.equal(validateEvidenceReceipt(sandboxReceipt, 'SANDBOX_VERIFICATION', 30 * 24 * 60 * 60 * 1000).valid, false);

// Recreate valid sandbox record after tamper test.
fs.rmSync(sandboxReceipt, { force: true });
const sandboxRun2 = spawnSync(process.execPath, [
  evidenceScript,
  '--confirm-evidence',
  '--type', 'SANDBOX_VERIFICATION',
  '--provider', 'truelayer',
  '--evidence-ref', 'TEST-SANDBOX-204-456',
  '--artifact', sandboxArtifact
], { encoding: 'utf8', cwd: evidenceRoot });
assert.equal(sandboxRun2.status, 0, sandboxRun2.stderr || sandboxRun2.stdout);

// Live config consumes the evidence files, not bare strings.
process.env.TRUELAYER_ENV = 'live';
process.env.G_BANK_ENABLE_LIVE = 'true';
process.env.G_BANK_SECRET_ROTATION_RECEIPT_FILE = rotationReceipt;
process.env.G_BANK_SANDBOX_VERIFICATION_RECEIPT_FILE = sandboxReceipt;
process.env.G_BANK_ALLOWED_BENEFICIARY_IBANS = 'NL91ABNA0417164300';
process.env.G_BANK_APPROVAL_SECRET = 'unit-test-approval-secret-012345678901234567890';
process.env.TRUELAYER_CLIENT_ID = 'test-client';
process.env.TRUELAYER_CLIENT_SECRET = 'test-secret';
process.env.TRUELAYER_SIGNING_KID = 'test-kid';
process.env.TRUELAYER_PRIVATE_KEY_PEM = syntheticPem;
process.env.TRUELAYER_RETURN_URI = 'https://example.invalid/return';

const evidenceLiveStatus = router._test.configStatus();
assert.equal(evidenceLiveStatus.historical_secret_rotation_receipt_present, true);
assert.equal(evidenceLiveStatus.sandbox_verification_receipt_present, true);
assert.equal(evidenceLiveStatus.configured, true);

fs.rmSync(evidenceRoot, { recursive: true, force: true });
console.log('Banking evidence integrity tests: PASS');


// TrueLayer webhook verification: exact JKU allowlist, JWKS kid, raw body and replay handling.
(async () => {
  process.env.TRUELAYER_ENV = 'sandbox';
  process.env.TRUELAYER_WEBHOOK_PATH = '/api/open-banking/webhook';

  const webhookPair = crypto.generateKeyPairSync('ec', { namedCurve: 'secp521r1' });
  const webhookKid = '44444444-4444-4444-8444-444444444444';
  const webhookJwk = webhookPair.publicKey.export({ format: 'jwk' });
  webhookJwk.kid = webhookKid;
  webhookJwk.alg = 'ES512';
  webhookJwk.use = 'sig';

  const webhookPath = '/api/open-banking/webhook';
  const webhookTimestamp = new Date().toISOString();
  const webhookEvent = {
    type: 'payment_executed',
    event_version: 1,
    event_id: '55555555-5555-4555-8555-555555555555',
    payment_id: '66666666-6666-4666-8666-666666666666'
  };
  const rawWebhookBody = Buffer.from(JSON.stringify(webhookEvent), 'utf8');
  const webhookHeaders = {
    'X-TL-Webhook-Timestamp': webhookTimestamp,
    'Content-Type': 'application/json'
  };
  const signedHeaderNames = ['X-TL-Webhook-Timestamp', 'Content-Type'];
  const webhookJoseHeader = {
    alg: 'ES512',
    kid: webhookKid,
    tl_version: '2',
    tl_headers: signedHeaderNames.join(','),
    jku: 'https://webhooks.truelayer-sandbox.com/.well-known/jwks'
  };
  const encodedWebhookHeader = Buffer.from(JSON.stringify(webhookJoseHeader)).toString('base64url');
  const webhookPayload = buildWebhookSigningPayload({
    method: 'POST',
    path: webhookPath,
    signedHeaders: signedHeaderNames,
    headers: webhookHeaders,
    body: rawWebhookBody.toString('utf8')
  });
  const webhookSigningInput = `${encodedWebhookHeader}.${Buffer.from(webhookPayload).toString('base64url')}`;
  const webhookRawSignature = crypto.sign('sha512', Buffer.from(webhookSigningInput), {
    key: webhookPair.privateKey,
    dsaEncoding: 'ieee-p1363'
  });
  const webhookSignature = `${encodedWebhookHeader}..${webhookRawSignature.toString('base64url')}`;

  assert.equal(expectedWebhookJku(), webhookJoseHeader.jku);
  assert.equal(parseDetachedTlSignature(webhookSignature).header.kid, webhookKid);
  assert.equal(validateWebhookTimestamp(webhookHeaders).timestamp, webhookTimestamp);

  const verification = verifyWebhookSignature({
    signature: webhookSignature,
    method: 'POST',
    path: webhookPath,
    headers: webhookHeaders,
    rawBody: rawWebhookBody,
    jwks: { keys: [webhookJwk] }
  });
  assert.equal(verification.valid, true);

  mustThrow(() => verifyWebhookSignature({
    signature: webhookSignature,
    method: 'POST',
    path: webhookPath,
    headers: webhookHeaders,
    rawBody: Buffer.from(JSON.stringify({ ...webhookEvent, type: 'payment_settled' })),
    jwks: { keys: [webhookJwk] }
  }), /invalid_webhook_signature/);

  const wrongJkuHeader = {
    ...webhookJoseHeader,
    jku: 'https://evil.example/.well-known/jwks'
  };
  const wrongEncodedHeader = Buffer.from(JSON.stringify(wrongJkuHeader)).toString('base64url');
  const wrongJkuSignature = `${wrongEncodedHeader}..${webhookRawSignature.toString('base64url')}`;
  mustThrow(() => parseDetachedTlSignature(wrongJkuSignature), /untrusted_header_jku/);

  const fetchCalls = [];
  const fakeWebhookHttp = {
    async get(url, options) {
      fetchCalls.push({ url, options });
      assert.equal(url, 'https://webhooks.truelayer-sandbox.com/.well-known/jwks');
      assert.equal(options.maxRedirects, 0);
      return { status: 200, data: { keys: [webhookJwk] } };
    }
  };

  const firstWebhook = await verifyAndClassifyWebhook({
    signature: webhookSignature,
    path: webhookPath,
    headers: webhookHeaders,
    rawBody: rawWebhookBody,
    httpClient: fakeWebhookHttp
  });
  assert.equal(firstWebhook.webhook_verified, true);
  assert.equal(firstWebhook.duplicate, false);
  assert.equal(firstWebhook.payment_write_performed, false);
  assert.equal(firstWebhook.value_moved_by_handler, false);
  assert.equal(firstWebhook.verified_value_flow, false);

  const duplicateWebhook = await verifyAndClassifyWebhook({
    signature: webhookSignature,
    path: webhookPath,
    headers: webhookHeaders,
    rawBody: rawWebhookBody,
    httpClient: fakeWebhookHttp
  });
  assert.equal(duplicateWebhook.webhook_verified, true);
  assert.equal(duplicateWebhook.duplicate, true);
  assert.equal(duplicateWebhook.verified_value_flow, false);
  assert.equal(fetchCalls.length, 2);

  console.log('TrueLayer webhook verification tests: PASS');
})().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
