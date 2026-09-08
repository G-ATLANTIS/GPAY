const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = process.cwd();
const envPath = path.join(root, '.env');
const secretsDir = path.join(root, '.secrets', 'truelayer');
const privatePath = path.join(secretsDir, 'ec512-private-key.pem');
const publicPath = path.join(secretsDir, 'ec512-public-key.pem');
const enableProbe = process.argv.includes('--enable-probe');

function parseEnv(text) {
  const map = new Map();
  const order = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.trim().startsWith('#') || !line.includes('=')) continue;
    const i = line.indexOf('=');
    const key = line.slice(0, i).trim();
    const value = line.slice(i + 1);
    if (!map.has(key)) order.push(key);
    map.set(key, value);
  }
  return { map, order };
}

function writeEnv(baseText, updates) {
  const lines = baseText.split(/\r?\n/);
  const seen = new Set();
  const output = lines.map(line => {
    if (!line || line.trim().startsWith('#') || !line.includes('=')) return line;
    const i = line.indexOf('=');
    const key = line.slice(0, i).trim();
    if (!(key in updates)) return line;
    seen.add(key);
    return `${key}=${updates[key]}`;
  });
  for (const [key, value] of Object.entries(updates)) {
    if (!seen.has(key)) output.push(`${key}=${value}`);
  }
  fs.writeFileSync(envPath, output.join('\n').replace(/\n*$/, '\n'), { mode: 0o600 });
}

function ensureKeypair() {
  if (fs.existsSync(privatePath) && fs.existsSync(publicPath)) return false;
  if (fs.existsSync(privatePath) !== fs.existsSync(publicPath)) {
    throw new Error('Partial TrueLayer keypair exists; resolve it manually before bootstrap.');
  }
  fs.mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'secp521r1' });
  fs.writeFileSync(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(publicPath, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
  return true;
}

function randomSecret() {
  return crypto.randomBytes(32).toString('hex');
}

function main() {
  if (!fs.existsSync(path.join(root, 'package.json'))) {
    throw new Error('Run this command from the GPAY repository root.');
  }

  let baseText = fs.existsSync(envPath)
    ? fs.readFileSync(envPath, 'utf8')
    : fs.readFileSync(path.join(root, '.env.example'), 'utf8');

  const { map } = parseEnv(baseText);
  const createdKeypair = ensureKeypair();
  const privateB64 = fs.readFileSync(privatePath).toString('base64');

  const updates = {
    TRUELAYER_ENV: 'sandbox',
    TRUELAYER_PRIVATE_KEY_B64: map.get('TRUELAYER_PRIVATE_KEY_B64') || privateB64,
    TRUELAYER_RETURN_URI: 'http://localhost:4000/api/open-banking/return',
    TRUELAYER_WEBHOOK_PATH: '/api/open-banking/webhook',
    G_BANK_WEBHOOK_RECEIPT_DIR: map.get('G_BANK_WEBHOOK_RECEIPT_DIR') || '.secrets/runtime/webhook-events',
    G_BANK_PAYMENT_INTENT_DIR: map.get('G_BANK_PAYMENT_INTENT_DIR') || '.secrets/runtime/payment-intents',
    G_BANK_MAX_PAYMENT_EUR: map.get('G_BANK_MAX_PAYMENT_EUR') || '100',
    G_BANK_ENABLE_LIVE: 'false',
    G_BANK_ENABLE_PROVIDER_PROBE: enableProbe ? 'true' : 'false',
    G_BANK_OPERATOR_SECRET: map.get('G_BANK_OPERATOR_SECRET') || randomSecret(),
    G_BANK_PROVIDER_PROBE_SECRET: map.get('G_BANK_PROVIDER_PROBE_SECRET') || randomSecret(),
    G_BANK_SMOKE_BASE_URL: map.get('G_BANK_SMOKE_BASE_URL') || 'http://127.0.0.1:4000',
    G_BANK_SANDBOX_SMOKE_BENEFICIARY_NAME: map.get('G_BANK_SANDBOX_SMOKE_BENEFICIARY_NAME') || 'G-Bank Sandbox Beneficiary',
    G_BANK_SANDBOX_SMOKE_REFERENCE: map.get('G_BANK_SANDBOX_SMOKE_REFERENCE') || 'GBANK-SMOKE'
  };

  writeEnv(baseText, updates);

  fs.mkdirSync(path.join(root, '.secrets', 'runtime', 'webhook-events'), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(root, '.secrets', 'runtime', 'payment-intents'), { recursive: true, mode: 0o700 });

  console.log('G-Bank sandbox bootstrap: COMPLETE');
  console.log('Keypair:', createdKeypair ? 'GENERATED' : 'REUSED');
  console.log('Public key:', publicPath);
  console.log('.env:', envPath);
  console.log('Live banking: DISABLED');
  console.log('Provider probe:', enableProbe ? 'ENABLED (sandbox only)' : 'DISABLED');
  console.log('');
  console.log('Still required from TrueLayer Console:');
  console.log('- TRUELAYER_CLIENT_ID');
  console.log('- TRUELAYER_CLIENT_SECRET');
  console.log('- TRUELAYER_SIGNING_KID');
  console.log('');
  console.log('Upload ONLY the public key shown above. Never upload/share the private key.');
}

try {
  main();
} catch (err) {
  console.error('G-Bank sandbox bootstrap: BLOCKED');
  console.error(err.message || err);
  process.exit(2);
}
