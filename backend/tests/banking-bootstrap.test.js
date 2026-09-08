const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const repoRoot = path.resolve(__dirname, '..', '..');
const script = path.join(repoRoot, 'scripts', 'bootstrap-banking-sandbox.js');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-bootstrap-'));

try {
  fs.writeFileSync(path.join(temp, 'package.json'), '{"name":"bootstrap-test"}\n');
  fs.writeFileSync(path.join(temp, '.env.example'), [
    'TRUELAYER_ENV=sandbox',
    'TRUELAYER_CLIENT_ID=',
    'TRUELAYER_CLIENT_SECRET=',
    'TRUELAYER_SIGNING_KID=',
    'TRUELAYER_PRIVATE_KEY_B64=',
    'TRUELAYER_RETURN_URI=http://localhost:4000/api/open-banking/return',
    'TRUELAYER_WEBHOOK_PATH=/api/open-banking/webhook',
    'G_BANK_WEBHOOK_RECEIPT_DIR=.secrets/runtime/webhook-events',
    'G_BANK_PAYMENT_INTENT_DIR=.secrets/runtime/payment-intents',
    'G_BANK_MAX_PAYMENT_EUR=100',
    'G_BANK_ENABLE_LIVE=false',
    'G_BANK_ENABLE_PROVIDER_PROBE=false',
    'G_BANK_PROVIDER_PROBE_SECRET=',
    'G_BANK_OPERATOR_SECRET=',
    'G_BANK_SMOKE_BASE_URL=http://127.0.0.1:4000',
    ''
  ].join('\n'));

  const first = spawnSync(process.execPath, [script, '--enable-probe'], {
    cwd: temp,
    encoding: 'utf8'
  });
  assert.equal(first.status, 0, first.stderr);
  assert.match(first.stdout, /G-Bank sandbox bootstrap: COMPLETE/);
  assert.match(first.stdout, /Live banking: DISABLED/);
  assert.match(first.stdout, /Provider probe: ENABLED/);

  const envPath = path.join(temp, '.env');
  const privatePath = path.join(temp, '.secrets', 'truelayer', 'ec512-private-key.pem');
  const publicPath = path.join(temp, '.secrets', 'truelayer', 'ec512-public-key.pem');
  assert.equal(fs.existsSync(envPath), true);
  assert.equal(fs.existsSync(privatePath), true);
  assert.equal(fs.existsSync(publicPath), true);

  const envText = fs.readFileSync(envPath, 'utf8');
  assert.match(envText, /^TRUELAYER_ENV=sandbox$/m);
  assert.match(envText, /^G_BANK_ENABLE_LIVE=false$/m);
  assert.match(envText, /^G_BANK_ENABLE_PROVIDER_PROBE=true$/m);
  assert.match(envText, /^G_BANK_OPERATOR_SECRET=[0-9a-f]{64}$/m);
  assert.match(envText, /^G_BANK_PROVIDER_PROBE_SECRET=[0-9a-f]{64}$/m);
  assert.match(envText, /^TRUELAYER_PRIVATE_KEY_B64=[A-Za-z0-9+/=]+$/m);
  assert.match(envText, /^TRUELAYER_CLIENT_ID=$/m);
  assert.match(envText, /^TRUELAYER_CLIENT_SECRET=$/m);
  assert.match(envText, /^TRUELAYER_SIGNING_KID=$/m);

  const envBefore = fs.readFileSync(envPath, 'utf8');
  const privateBefore = fs.readFileSync(privatePath, 'utf8');
  const second = spawnSync(process.execPath, [script, '--enable-probe'], {
    cwd: temp,
    encoding: 'utf8'
  });
  assert.equal(second.status, 0, second.stderr);
  assert.match(second.stdout, /Keypair: REUSED/);
  assert.equal(fs.readFileSync(privatePath, 'utf8'), privateBefore);

  const envAfter = fs.readFileSync(envPath, 'utf8');
  const opBefore = envBefore.match(/^G_BANK_OPERATOR_SECRET=(.+)$/m)[1];
  const opAfter = envAfter.match(/^G_BANK_OPERATOR_SECRET=(.+)$/m)[1];
  const probeBefore = envBefore.match(/^G_BANK_PROVIDER_PROBE_SECRET=(.+)$/m)[1];
  const probeAfter = envAfter.match(/^G_BANK_PROVIDER_PROBE_SECRET=(.+)$/m)[1];
  assert.equal(opAfter, opBefore);
  assert.equal(probeAfter, probeBefore);

  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(envPath).mode & 0o777, 0o600);
    assert.equal(fs.statSync(privatePath).mode & 0o777, 0o600);
  }

  console.log('G-Bank sandbox bootstrap tests: PASS');
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}
