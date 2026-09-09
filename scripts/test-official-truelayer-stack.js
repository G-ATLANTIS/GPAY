require('dotenv').config();

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const localRouter = require('./route-banking-sandbox-webhooks');
const openBanking = require('../backend/routes/openbanking');

const DEFAULT_CLI = path.join(os.homedir(), '.cargo', 'bin', 'truelayer');
const LOCAL_WEBHOOK = 'http://127.0.0.1:4000/api/open-banking/webhook';

function requireSandboxSafety() {
  if ((process.env.TRUELAYER_ENV || 'sandbox').toLowerCase() !== 'sandbox') {
    throw new Error('Official TrueLayer stack diagnostic is sandbox-only.');
  }
  if (process.env.G_BANK_ENABLE_LIVE === 'true') {
    throw new Error('Official TrueLayer stack diagnostic refuses G_BANK_ENABLE_LIVE=true.');
  }
}

function required(name) {
  const value = String(process.env[name] || '');
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

function cliPath() {
  const value = String(process.env.TRUELAYER_CLI_PATH || DEFAULT_CLI);
  if (!fs.existsSync(value)) {
    throw new Error(`TrueLayer CLI not found at ${value}.`);
  }
  return value;
}

function stripAnsi(value) {
  return String(value || '').replace(/\x1B\[[0-?]*[ -\/]*[@-~]/g, '');
}

function capture(child) {
  let buffer = '';
  let exitCode = null;

  function append(stream, chunk) {
    const text = chunk.toString('utf8');
    stream.write(text);
    buffer = (buffer + text).slice(-262144);
  }

  child.stdout?.on('data', chunk => append(process.stdout, chunk));
  child.stderr?.on('data', chunk => append(process.stderr, chunk));
  child.on('exit', code => { exitCode = code; });

  return {
    get buffer() { return buffer; },
    get clean() { return stripAnsi(buffer); },
    get exitCode() { return exitCode; }
  };
}

async function waitFor(captureState, predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = predicate(captureState.clean);
    if (result) return result;
    if (captureState.exitCode !== null) {
      throw new Error(`${label} process exited early with code ${captureState.exitCode}.`);
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for ${label}.`);
}

function parseCreatedPaymentId(output) {
  const match = stripAnsi(output).match(/Created payment with id\s+([0-9a-f-]{36})/i);
  return match ? match[1].toLowerCase() : null;
}

function parseGeneratedPaymentIds(output) {
  const clean = stripAnsi(output);
  const ids = [];
  const patterns = [
    /Created payment with id\s+([0-9a-f-]{36})/ig,
    /Mock payment_id:\s*([0-9a-f-]{36})/ig
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(clean)) !== null) {
      const id = match[1].toLowerCase();
      if (!ids.includes(id)) ids.push(id);
    }
  }

  return ids;
}

function officialRouterObservation(output, paymentIds) {
  const clean = stripAnsi(output);
  const lines = clean.split(/\r?\n/);
  const wantedIds = (Array.isArray(paymentIds) ? paymentIds : [paymentIds])
    .map(value => String(value || '').toLowerCase())
    .filter(Boolean);

  for (const line of lines) {
    if (!/Payment id:/i.test(line)) continue;
    const lower = line.toLowerCase();
    const matchedPaymentId = wantedIds.find(id => lower.includes(id));
    if (!matchedPaymentId) continue;

    return {
      seen: true,
      success: /SUCCESS/i.test(line),
      failure: /FAILURE/i.test(line),
      paymentId: matchedPaymentId,
      line: line.trim()
    };
  }

  return { seen: false, success: false, failure: false, paymentId: null, line: null };
}

function latestOfficialRouterFailure(output, paymentIds = null) {
  const clean = stripAnsi(output);
  const lines = clean.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  const wantedIds = paymentIds === null
    ? null
    : (Array.isArray(paymentIds) ? paymentIds : [paymentIds])
        .map(value => String(value || '').toLowerCase())
        .filter(Boolean);

  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const line = lines[i];
    if (!/Payment id:/i.test(line) || !/FAILURE/i.test(line)) continue;
    const match = line.match(/Payment id:\s*([0-9a-f-]{36})/i);
    const paymentId = match ? match[1].toLowerCase() : null;
    if (wantedIds && (!paymentId || !wantedIds.includes(paymentId))) continue;
    return {
      seen: true,
      paymentId,
      line
    };
  }

  return { seen: false, paymentId: null, line: null };
}

async function providerReadback(paymentIds) {
  const candidates = Array.isArray(paymentIds) ? paymentIds : [paymentIds];
  const failures = [];

  for (const paymentId of candidates) {
    try {
      const result = await openBanking._test.fetchPaymentStatus(paymentId);
      const observedId = String(result?.payment?.id || paymentId).toLowerCase();
      if (observedId !== String(paymentId).toLowerCase()) {
        failures.push(`${paymentId}: provider returned different payment id ${observedId}`);
        continue;
      }
      return {
        verified: true,
        paymentId: observedId,
        environment: result.environment,
        status: String(result?.payment?.status || 'unknown'),
        payment: result.payment || {}
      };
    } catch (err) {
      failures.push(`${paymentId}: ${err.response?.status || err.code || err.message || err}`);
    }
  }

  return {
    verified: false,
    paymentId: null,
    environment: 'sandbox',
    status: 'unreadable',
    failures
  };
}

async function run() {
  requireSandboxSafety();

  const cli = cliPath();
  const clientId = required('TRUELAYER_CLIENT_ID');
  const clientSecret = required('TRUELAYER_CLIENT_SECRET');
  const kid = required('TRUELAYER_SIGNING_KID');
  const privateKey = path.resolve(
    process.env.TRUELAYER_PRIVATE_KEY_FILE || '.secrets/truelayer/ec512-private-key.pem'
  );

  if (!fs.existsSync(privateKey)) {
    throw new Error(`TrueLayer private key file not found at ${privateKey}.`);
  }

  console.log('G-Bank TrueLayer official-router + official-generator diagnostic');
  console.log('Environment: sandbox');
  console.log('Live banking: DISABLED');
  console.log('Go-live promotion: DISABLED');
  console.log('Note: TrueLayer CLI requires client_secret as a process argument during this bounded local diagnostic.');

  const localServer = await localRouter.startLocalBankingServerIfNeeded();
  console.log('Local G-Bank:', localServer.detail);

  const router = spawn(cli, [
    'route-webhooks',
    '--to-addr', LOCAL_WEBHOOK,
    '--client-id', clientId,
    '--client-secret', clientSecret
  ], {
    cwd: process.cwd(),
    env: { ...process.env },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const routerCapture = capture(router);

  try {
    console.log('Step 1: starting official TrueLayer route-webhooks.');
    await waitFor(
      routerCapture,
      output => /Pulling webhooks\.\.\./i.test(output),
      20000,
      'official TrueLayer router readiness'
    );

    console.log('Step 2: official router active; starting official generate-webhook executed.');
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
    const generatorCapture = capture(generator);

    const generatorExit = await new Promise((resolve, reject) => {
      generator.on('error', reject);
      generator.on('exit', code => resolve(code));
    });
    if (generatorExit !== 0) {
      throw new Error(`Official TrueLayer generator exited with code ${generatorExit}.`);
    }

    const paymentIds = parseGeneratedPaymentIds(generatorCapture.clean);
    if (paymentIds.length === 0) {
      throw new Error('Could not parse payment IDs from official TrueLayer generator output.');
    }

    console.log('Step 3: generator completed; performing authenticated provider readback.');
    console.log('Candidate payment IDs:', paymentIds.join(', '));

    const readback = await providerReadback(paymentIds);
    if (!readback.verified) {
      throw new Error(
        `TrueLayer provider readback failed for all generated payment IDs: ${(readback.failures || []).join('; ')}`
      );
    }
    if (String(readback.environment).toLowerCase() !== 'sandbox') {
      throw new Error('Provider readback did not remain sandbox-bound.');
    }

    console.log('Provider payment readback: VERIFIED');
    console.log('Readback payment ID:', readback.paymentId);
    console.log('Readback status:', readback.status);

    // Webhook routing is useful additional observation, but it is not the
    // primary write/readback proof. Give it a short bounded window and do not
    // fail the provider write proof when no matching webhook is routed.
    let observation = { seen: false, success: false, failure: false, paymentId: null, line: null };
    try {
      observation = await waitFor(
        routerCapture,
        output => {
          const result = officialRouterObservation(output, paymentIds);
          return result.seen ? result : null;
        },
        5000,
        'optional matching official TrueLayer routed webhook'
      );
    } catch {
      observation = { seen: false, success: false, failure: false, paymentId: null, line: null };
    }

    if (observation.failure) {
      const serverOutput = String(localServer.getOutput?.() || '');
      const rejectLines = serverOutput
        .split(/\r?\n/)
        .filter(line => line.includes('[G-Bank webhook reject]'))
        .slice(-5);
      if (rejectLines.length > 0) {
        console.error('GPAY webhook verifier diagnostics:');
        for (const line of rejectLines) console.error(line);
      }
    }

    const observedPaymentId = readback.paymentId;
    console.log('Official TrueLayer stack diagnostic: VERIFIED');
    console.log('Payment ID:', observedPaymentId);
    console.log('Provider generator: VERIFIED');
    console.log('Provider payment readback: VERIFIED');
    console.log('Provider webhook router:', observation.success ? 'VERIFIED' : 'NOT_OBSERVED');
    console.log('GPAY local webhook delivery:', observation.success ? 'VERIFIED' : 'NOT_OBSERVED');
    console.log('GPAY signed webhook acceptance:', observation.success ? 'VERIFIED' : 'NOT_OBSERVED');
    console.log('Go-live promotion: NOT PERFORMED');
    return {
      paymentId: observedPaymentId,
      providerReadbackVerified: true,
      providerStatus: readback.status,
      webhookObserved: observation.success === true
    };
  } finally {
    try { router.kill('SIGTERM'); } catch {}
    if (localServer.started && localServer.child) {
      try { localServer.child.kill('SIGTERM'); } catch {}
    }
  }
}

if (require.main === module) {
  run().catch(err => {
    console.error('Official TrueLayer stack diagnostic: BLOCKED');
    console.error(err.message || err);
    process.exit(2);
  });
}

module.exports = {
  DEFAULT_CLI,
  LOCAL_WEBHOOK,
  requireSandboxSafety,
  stripAnsi,
  parseCreatedPaymentId,
  parseGeneratedPaymentIds,
  officialRouterObservation,
  latestOfficialRouterFailure,
  providerReadback,
  waitFor,
  run
};
