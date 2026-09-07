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
  signRequest
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
mustThrow(() => assertProviderProbeEnabled(), /disabled/);
assert.equal(providerConfigStatus().provider_probe_enabled, false);

process.env.G_BANK_ENABLE_PROVIDER_PROBE = 'true';
assert.doesNotThrow(() => assertProviderProbeEnabled());
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
