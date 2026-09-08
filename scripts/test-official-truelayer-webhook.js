require('dotenv').config();

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const ROUTER_SCRIPT = path.resolve(process.cwd(), 'scripts', 'route-banking-sandbox-webhooks.js');
const DEFAULT_CLI = path.join(os.homedir(), '.cargo', 'bin', 'truelayer');

function requireSandboxSafety() {
  if ((process.env.TRUELAYER_ENV || 'sandbox').toLowerCase() !== 'sandbox') {
    throw new Error('Official TrueLayer webhook diagnostic is sandbox-only.');
  }
  if (process.env.G_BANK_ENABLE_LIVE === 'true') {
    throw new Error('Official TrueLayer webhook diagnostic refuses G_BANK_ENABLE_LIVE=true.');
  }
}

function cliPath() {
  const value = String(process.env.TRUELAYER_CLI_PATH || DEFAULT_CLI);
  if (!fs.existsSync(value)) {
    throw new Error(`TrueLayer CLI not found at ${value}. Install it with cargo --locked first.`);
  }
  return value;
}

function required(name) {
  const value = String(process.env[name] || '');
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function parseOfficialPaymentId(text) {
  const match = String(text || '').match(/Created payment with id\s+([0-9a-f-]{36})/i);
  return match ? match[1].toLowerCase() : null;
}

function parseForwardedPaymentId(text) {
  const match = String(text || '').match(/Webhook VERIFIED\/FORWARDED[^\n]*payment_id=([0-9a-f-]{36})/i);
  return match ? match[1].toLowerCase() : null;
}

function captureChildOutput(child) {
  let buffer = '';
  let exitCode = null;

  function append(stream, chunk) {
    const text = chunk.toString('utf8');
    stream.write(text);
    buffer = (buffer + text).slice(-131072);
  }

  child.stdout?.on('data', chunk => append(process.stdout, chunk));
  child.stderr?.on('data', chunk => append(process.stderr, chunk));
  child.on('exit', code => { exitCode = code; });

  return {
    get buffer() { return buffer; },
    get exitCode() { return exitCode; }
  };
}

async function waitForCaptured(capture, predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = predicate(capture.buffer);
    if (result) return result;
    if (capture.exitCode !== null) {
      throw new Error(`${label} process exited early with code ${capture.exitCode}.`);
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for ${label}.`);
}

async function run() {
  requireSandboxSafety();

  const cli = cliPath();
  const privateKey = path.resolve(
    process.env.TRUELAYER_PRIVATE_KEY_FILE || '.secrets/truelayer/ec512-private-key.pem'
  );
  if (!fs.existsSync(privateKey)) {
    throw new Error(`TrueLayer private key file not found at ${privateKey}.`);
  }

  const clientId = required('TRUELAYER_CLIENT_ID');
  const clientSecret = required('TRUELAYER_CLIENT_SECRET');
  const kid = required('TRUELAYER_SIGNING_KID');

  console.log('G-Bank official TrueLayer webhook diagnostic');
  console.log('Environment: sandbox');
  console.log('Live banking: DISABLED');
  console.log('Step 1: starting localhost webhook router before generator...');

  const router = spawn(process.execPath, [ROUTER_SCRIPT], {
    cwd: process.cwd(),
    env: { ...process.env },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  const routerCapture = captureChildOutput(router);

  try {
    await waitForCaptured(
      routerCapture,
      output => output.includes('Polling for queued webhooks every 5 seconds...'),
      20000,
      'webhook router readiness'
    );

    console.log('Step 2: router is active; starting official TrueLayer generator.');

    const generator = spawn(cli, [
      'generate-webhook',
      '--private-key', privateKey,
      '--client-id', clientId,
      '--client-secret', clientSecret,
      '--kid', kid,
      'executed'
    ], {
      cwd: process.cwd(),
      env: { ...process.env },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let generatorOutput = '';
    generator.stdout.on('data', chunk => {
      const text = chunk.toString('utf8');
      process.stdout.write(text);
      generatorOutput += text;
    });
    generator.stderr.on('data', chunk => {
      const text = chunk.toString('utf8');
      process.stderr.write(text);
      generatorOutput += text;
    });

    const generatorExit = await new Promise((resolve, reject) => {
      generator.on('error', reject);
      generator.on('exit', code => resolve(code));
    });

    if (generatorExit !== 0) {
      throw new Error(`Official TrueLayer generator exited with code ${generatorExit}.`);
    }

    const paymentId = parseOfficialPaymentId(generatorOutput);
    if (!paymentId) {
      throw new Error('Could not parse official TrueLayer payment ID from generator output.');
    }

    console.log('Step 3: official generator completed; waiting for matching routed webhook.');
    const forwardedId = await waitForCaptured(
      routerCapture,
      output => {
        const matches = [...String(output).matchAll(/Webhook VERIFIED\/FORWARDED[^\n]*payment_id=([0-9a-f-]{36})/ig)];
        for (const match of matches) {
          if (String(match[1]).toLowerCase() === paymentId) return paymentId;
        }
        return null;
      },
      60000,
      'matching TrueLayer webhook'
    );

    if (forwardedId !== paymentId) {
      throw new Error('Webhook router returned a different payment ID.');
    }

    console.log('Official TrueLayer webhook diagnostic: VERIFIED');
    console.log('Payment ID:', paymentId);
    console.log('This proves provider generator -> router -> GPAY signed webhook verification.');
    console.log('Go-live promotion: NOT PERFORMED');
    return paymentId;
  } finally {
    try { router.kill('SIGTERM'); } catch {}
  }
}

if (require.main === module) {
  run().catch(err => {
    console.error('Official TrueLayer webhook diagnostic: BLOCKED');
    console.error(err.message || err);
    process.exit(2);
  });
}

module.exports = {
  DEFAULT_CLI,
  requireSandboxSafety,
  cliPath,
  captureChildOutput,
  waitForCaptured,
  parseOfficialPaymentId,
  parseForwardedPaymentId,
  run
};
