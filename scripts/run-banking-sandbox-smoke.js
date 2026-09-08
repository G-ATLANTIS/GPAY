require('dotenv').config();

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const baseUrl = String(process.env.G_BANK_SMOKE_BASE_URL || 'http://127.0.0.1:4000').replace(/\/$/, '');
const smokeRoot = path.resolve(process.cwd(), '.secrets', 'smoke');


async function localServerReachable() {
  try {
    const response = await fetch(`${baseUrl}/`, {
      signal: AbortSignal.timeout(1000)
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function startLocalServerIfNeeded() {
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new Error('G_BANK_SMOKE_BASE_URL is invalid.');
  }

  if (!['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname)) {
    return { child: null, started: false };
  }

  if (await localServerReachable()) {
    return { child: null, started: false };
  }

  const child = spawn(process.execPath, ['backend/banking-server.js'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: parsed.port || process.env.PORT || '4000'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let output = '';
  child.stdout.on('data', chunk => {
    output = (output + chunk.toString('utf8')).slice(-4096);
  });
  child.stderr.on('data', chunk => {
    output = (output + chunk.toString('utf8')).slice(-4096);
  });

  const deadline = Date.now() + 6000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      const last = output.split('\n').map(v => v.trim()).filter(Boolean).slice(-1)[0] || '';
      throw new Error(`Local G-Bank server exited early with code ${child.exitCode}${last ? `: ${last}` : ''}`);
    }
    if (await localServerReachable()) {
      return { child, started: true };
    }
    await new Promise(resolve => setTimeout(resolve, 200));
  }

  try { child.kill('SIGTERM'); } catch {}
  const last = output.split('\n').map(v => v.trim()).filter(Boolean).slice(-1)[0] || '';
  throw new Error(`Local G-Bank server did not become reachable${last ? `: ${last}` : ''}`);
}

async function withLocalServer(fn) {
  const server = await startLocalServerIfNeeded();
  try {
    return await fn();
  } finally {
    if (server.started && server.child) {
      try { server.child.kill('SIGTERM'); } catch {}
    }
  }
}

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : null;
}

function requireSandbox() {
  if ((process.env.TRUELAYER_ENV || 'sandbox').toLowerCase() !== 'sandbox') {
    throw new Error('Sandbox smoke command refuses to run unless TRUELAYER_ENV=sandbox.');
  }
  if (process.env.G_BANK_ENABLE_LIVE === 'true') {
    throw new Error('Sandbox smoke command refuses to run while G_BANK_ENABLE_LIVE=true.');
  }
}

function requireSecret(name) {
  const value = process.env[name] || '';
  if (value.length < 32) {
    throw new Error(`${name} must be configured with at least 32 characters.`);
  }
  return value;
}

function safeTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function writeJsonArtifact(prefix, payload) {
  fs.mkdirSync(smokeRoot, { recursive: true, mode: 0o700 });
  const filePath = path.join(smokeRoot, `${prefix}-${safeTimestamp()}.json`);
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  return filePath;
}

function writeSecretText(filename, value) {
  fs.mkdirSync(smokeRoot, { recursive: true, mode: 0o700 });
  const filePath = path.join(smokeRoot, filename);
  fs.writeFileSync(filePath, String(value) + '\n', { mode: 0o600, flag: 'wx' });
  return filePath;
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw_response_sha256: crypto.createHash('sha256').update(text).digest('hex') };
  }
  if (!response.ok) {
    const err = new Error(`HTTP ${response.status} from G-Bank endpoint.`);
    err.statusCode = response.status;
    err.body = body;
    throw err;
  }
  return body;
}

function operatorHeaders(extra = {}) {
  return {
    'X-G-Bank-Operator-Authorization': requireSecret('G_BANK_OPERATOR_SECRET'),
    ...extra
  };
}

async function probe() {
  requireSandbox();
  if (process.env.G_BANK_ENABLE_PROVIDER_PROBE !== 'true') {
    throw new Error('Set G_BANK_ENABLE_PROVIDER_PROBE=true only for the readiness probe.');
  }
  const body = await requestJson(`${baseUrl}/api/open-banking/provider-readiness`, {
    method: 'POST',
    headers: operatorHeaders({
      'X-G-Bank-Probe-Authorization': requireSecret('G_BANK_PROVIDER_PROBE_SECRET'),
      'Content-Type': 'application/json'
    }),
    body: '{}'
  });

  if (
    body.environment !== 'sandbox' ||
    body.access_token_obtained !== true ||
    body.request_signature_accepted !== true ||
    body.provider_http_status !== 204 ||
    body.payment_created !== false ||
    body.value_moved !== false ||
    body.verified_value_flow !== false
  ) {
    throw new Error('Provider readiness response did not satisfy the sandbox 204 proof contract.');
  }

  const artifact = writeJsonArtifact('provider-readiness', body);
  console.log('Provider readiness: PASS');
  console.log('Artifact:', artifact);
  console.log('No payment was created and no value was moved.');
  return body;
}

async function createPayment() {
  requireSandbox();
  if (!process.argv.includes('--confirm-sandbox-payment')) {
    throw new Error('Refusing to create even a sandbox payment without --confirm-sandbox-payment.');
  }

  const amount = String(arg('--amount-eur') || '0.01');
  if (!/^\d+(?:\.\d{1,2})?$/.test(amount)) throw new Error('--amount-eur must have at most two decimals.');
  const amountNumber = Number(amount);
  if (!Number.isFinite(amountNumber) || amountNumber <= 0 || amountNumber > 1) {
    throw new Error('Sandbox smoke amount must be > 0 and <= EUR 1.00.');
  }

  const iban = String(process.env.G_BANK_SANDBOX_SMOKE_BENEFICIARY_IBAN || '').replace(/\s+/g, '').toUpperCase();
  if (!iban) throw new Error('G_BANK_SANDBOX_SMOKE_BENEFICIARY_IBAN is required.');
  const beneficiaryName = String(process.env.G_BANK_SANDBOX_SMOKE_BENEFICIARY_NAME || 'G-Bank Sandbox Beneficiary');
  const reference = String(process.env.G_BANK_SANDBOX_SMOKE_REFERENCE || 'GBANK-SMOKE').slice(0, 18);
  const idempotencyKey = crypto.randomUUID();

  const payload = {
    amount_eur: amount,
    beneficiary: {
      name: beneficiaryName,
      iban,
      reference
    },
    user: {
      name: 'G-Bank Sandbox User',
      email: 'sandbox-user@example.invalid',
      phone: '+31600000000',
      date_of_birth: '1990-01-01',
      address: {
        address_line1: 'Sandboxstraat 1',
        city: 'Amsterdam',
        zip: '1000AA',
        country_code: 'NL'
      }
    }
  };

  const body = await requestJson(`${baseUrl}/api/open-banking/create-payment`, {
    method: 'POST',
    headers: operatorHeaders({
      'Content-Type': 'application/json',
      'Idempotency-Key': idempotencyKey
    }),
    body: JSON.stringify(payload)
  });

  if (
    body.environment !== 'sandbox' ||
    !body.payment_id ||
    body.authorization_required !== true ||
    !body.authorization_url
  ) {
    throw new Error('Sandbox payment creation response did not contain the expected HPP authorization data.');
  }

  const authorizationUrl = body.authorization_url;
  const publicArtifact = {
    ...body,
    authorization_url: undefined,
    authorization_url_sha256: crypto.createHash('sha256').update(authorizationUrl).digest('hex')
  };
  delete publicArtifact.authorization_url;

  const artifact = writeJsonArtifact(`payment-created-${body.payment_id}`, publicArtifact);
  const hppFile = writeSecretText(`hpp-${body.payment_id}.url`, authorizationUrl);

  console.log('Sandbox payment object created.');
  console.log('Payment ID:', body.payment_id);
  console.log('Artifact:', artifact);
  console.log('HPP URL file:', hppFile);
  console.log('Open that local file and use the Hosted Payment Page.');
  console.log('For the Dutch mock redirect flow, choose Mock Netherlands Payments - Redirect Flow.');
  console.log('Use username test_executed in the mock bank to simulate execution.');
  console.log('No live payment can be created by this smoke command.');
  return body;
}

async function status(paymentId) {
  requireSandbox();
  if (!/^[0-9a-f-]{36}$/i.test(String(paymentId || ''))) throw new Error('--payment-id must be a UUID.');
  const body = await requestJson(`${baseUrl}/api/open-banking/payment/${paymentId}`, {
    headers: operatorHeaders()
  });
  const artifact = writeJsonArtifact(`payment-status-${paymentId}`, body);
  console.log('Provider status artifact:', artifact);
  console.log('Status:', body.status || 'unknown');
  console.log('Verified value flow:', body.verified_value_flow === true ? 'TRUE' : 'FALSE');
  return body;
}

async function reconcile(paymentId) {
  requireSandbox();
  if (!/^[0-9a-f-]{36}$/i.test(String(paymentId || ''))) throw new Error('--payment-id must be a UUID.');
  const body = await requestJson(`${baseUrl}/api/open-banking/payment/${paymentId}/reconcile`, {
    headers: operatorHeaders()
  });
  const artifact = writeJsonArtifact(`payment-reconcile-${paymentId}`, body);
  console.log('Reconciliation artifact:', artifact);
  console.log('State:', body.reconciliation?.state || 'unknown');
  console.log('Creditor settlement proven:', body.creditor_settlement_proven === true ? 'TRUE' : 'FALSE');
  console.log('Verified value flow:', body.verified_value_flow === true ? 'TRUE' : 'FALSE');
  return body;
}

async function main() {
  const command = process.argv[2];
  if (!['probe', 'create', 'status', 'reconcile'].includes(command)) {
    console.error('Usage: npm run smoke:banking -- <probe|create|status|reconcile> [options]');
    process.exit(2);
  }

  try {
    await withLocalServer(async () => {
      if (command === 'probe') await probe();
      if (command === 'create') await createPayment();
      if (command === 'status') await status(arg('--payment-id'));
      if (command === 'reconcile') await reconcile(arg('--payment-id'));
    });
  } catch (err) {
    console.error('Sandbox Banking smoke: BLOCKED');
    console.error(err.message || err);
    if (err.body) console.error(JSON.stringify(err.body, null, 2));
    process.exit(2);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  requireSandbox,
  probe,
  createPayment,
  status,
  reconcile,
  localServerReachable,
  startLocalServerIfNeeded,
  withLocalServer
};
