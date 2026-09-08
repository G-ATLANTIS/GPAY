require('dotenv').config();

const { spawn } = require('node:child_process');

const ROUTER_URL = 'https://webhook-router.truelayer-sandbox.com/pull';
const DEFAULT_DESTINATION = 'http://127.0.0.1:4000/api/open-banking/webhook';
const POLL_MS = 5000;

function requireSandboxSafety() {
  if ((process.env.TRUELAYER_ENV || 'sandbox').toLowerCase() !== 'sandbox') {
    throw new Error('Webhook router is sandbox-only: TRUELAYER_ENV must be sandbox.');
  }
  if (process.env.G_BANK_ENABLE_LIVE === 'true') {
    throw new Error('Webhook router refuses to run while G_BANK_ENABLE_LIVE=true.');
  }
}

function destinationUrl() {
  const value = String(process.env.G_BANK_WEBHOOK_ROUTER_TO || DEFAULT_DESTINATION);
  const parsed = new URL(value);
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname)) {
    throw new Error('Sandbox webhook router destination must be localhost.');
  }
  if (parsed.pathname !== '/api/open-banking/webhook') {
    throw new Error('Sandbox webhook router destination path must be /api/open-banking/webhook.');
  }
  return parsed.toString().replace(/\/$/, '');
}


async function localDestinationReachable(fetchFn = fetch) {
  try {
    const parsed = new URL(destinationUrl());
    const root = `${parsed.protocol}//${parsed.host}/`;
    const response = await fetchFn(root, { signal: AbortSignal.timeout(1000) });
    return response.ok;
  } catch {
    return false;
  }
}

async function startLocalBankingServerIfNeeded() {
  if (await localDestinationReachable()) {
    return {
      started: false,
      child: null,
      detail: 'existing local G-Bank server detected',
      getOutput: () => ''
    };
  }

  const parsed = new URL(destinationUrl());
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
    if (await localDestinationReachable()) {
      return {
        started: true,
        child,
        detail: 'temporary local G-Bank server started',
        getOutput: () => output
      };
    }
    await new Promise(resolve => setTimeout(resolve, 200));
  }

  try { child.kill('SIGTERM'); } catch {}
  throw new Error('Local G-Bank server did not become reachable.');
}

function credentials() {
  const clientId = process.env.TRUELAYER_CLIENT_ID || '';
  const clientSecret = process.env.TRUELAYER_CLIENT_SECRET || '';
  if (!clientId || !clientSecret) {
    throw new Error('TRUELAYER_CLIENT_ID and TRUELAYER_CLIENT_SECRET are required.');
  }
  return { clientId, clientSecret };
}

async function getAccessToken(fetchFn = fetch) {
  requireSandboxSafety();
  const { clientId, clientSecret } = credentials();
  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret,
    scope: 'payments'
  });
  const response = await fetchFn('https://auth.truelayer-sandbox.com/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
    signal: AbortSignal.timeout(15000)
  });
  const text = await response.text();
  let body = {};
  try { body = text ? JSON.parse(text) : {}; } catch {}
  if (!response.ok || !body.access_token) {
    throw new Error(`TrueLayer token request failed with HTTP ${response.status}.`);
  }
  return body.access_token;
}

function sanitizedForwardHeaders(input) {
  const blocked = new Set(['host', 'content-length', 'connection', 'transfer-encoding']);
  const out = {};
  for (const [key, value] of Object.entries(input || {})) {
    if (!blocked.has(String(key).toLowerCase())) out[key] = String(value);
  }
  return out;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function safeNetworkCause(err) {
  const code = err?.cause?.code || err?.code || '';
  const name = err?.cause?.name || err?.name || '';
  if (code) return String(code).slice(0, 80);
  if (name) return String(name).slice(0, 80);
  return 'UNKNOWN_NETWORK_ERROR';
}

function transientHttpStatus(status) {
  return status === 429 || (status >= 500 && status <= 599);
}

async function pullWebhooks(token, fetchFn = fetch, {
  maxRetries = 3,
  sleepFn = sleep
} = {}) {
  let lastError = null;

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    try {
      const response = await fetchFn(ROUTER_URL, {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(30000)
      });

      if (response.status === 401) return { unauthorized: true, webhooks: [], attempts: attempt + 1 };

      if (!response.ok) {
        if (transientHttpStatus(response.status) && attempt < maxRetries) {
          await sleepFn(500 * (2 ** attempt));
          continue;
        }
        throw new Error(`TrueLayer webhook pull failed with HTTP ${response.status} after ${attempt + 1} attempt(s).`);
      }

      const body = await response.json();
      if (!body || !Array.isArray(body.webhooks)) {
        throw new Error('TrueLayer webhook router returned an invalid payload.');
      }
      return { unauthorized: false, webhooks: body.webhooks, attempts: attempt + 1 };
    } catch (err) {
      lastError = err;
      const isHttpError = /^TrueLayer webhook pull failed with HTTP/.test(String(err?.message || ''));
      const isInvalidPayload = String(err?.message || '') === 'TrueLayer webhook router returned an invalid payload.';

      if (isInvalidPayload || (isHttpError && !/HTTP (429|5\d\d)/.test(String(err.message)))) {
        throw err;
      }

      if (attempt >= maxRetries) {
        if (isHttpError) throw err;
        const cause = safeNetworkCause(err);
        throw new Error(
          `TrueLayer webhook pull network failure after ${attempt + 1} attempt(s); cause=${cause}`
        );
      }

      await sleepFn(500 * (2 ** attempt));
    }
  }

  const cause = safeNetworkCause(lastError);
  throw new Error(`TrueLayer webhook pull network failure; cause=${cause}`);
}

async function forwardWebhook(webhook, fetchFn = fetch) {
  if (!webhook || typeof webhook.body !== 'string' || !webhook.headers || typeof webhook.headers !== 'object') {
    throw new Error('Malformed webhook from TrueLayer router.');
  }

  let event = {};
  try { event = JSON.parse(webhook.body); } catch {}

  const response = await fetchFn(destinationUrl(), {
    method: 'POST',
    headers: sanitizedForwardHeaders(webhook.headers),
    body: webhook.body,
    signal: AbortSignal.timeout(15000)
  });

  const paymentId = event.payment_id || 'unknown';
  const eventId = event.event_id || 'unknown';
  const type = event.type || 'unknown';

  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(
      `Local G-Bank rejected webhook: HTTP ${response.status}; type=${type}; event_id=${eventId}; payment_id=${paymentId}` +
      (detail ? `; response=${detail.slice(0, 300)}` : '')
    );
  }

  console.log(`Webhook VERIFIED/FORWARDED type=${type} event_id=${eventId} payment_id=${paymentId} http=${response.status}`);
  return { type, eventId, paymentId, status: response.status };
}

async function runOnce(token, fetchFn = fetch) {
  const pulled = await pullWebhooks(token, fetchFn);
  if (pulled.unauthorized) return { refreshToken: true, pulled: 0, forwarded: [] };
  const forwarded = [];
  for (const webhook of pulled.webhooks) {
    forwarded.push(await forwardWebhook(webhook, fetchFn));
  }
  return { refreshToken: false, pulled: pulled.webhooks.length, forwarded };
}

async function main() {
  requireSandboxSafety();
  console.log('G-Bank native TrueLayer sandbox webhook router');
  console.log('Pull:', ROUTER_URL);
  console.log('Forward:', destinationUrl());
  console.log('Live banking: DISABLED');
  console.log('Credentials: loaded from .env (not command-line arguments)');

  const localServer = await startLocalBankingServerIfNeeded();
  console.log('Local G-Bank:', localServer.detail);

  let token = await getAccessToken();
  console.log('TrueLayer sandbox token: OK');

  if (process.argv.includes('--once')) {
    try {
      const result = await runOnce(token);
      if (result.refreshToken) {
        token = await getAccessToken();
        const retry = await runOnce(token);
        console.log(`Queued webhooks pulled: ${retry.pulled}`);
        console.log(`Webhooks verified/forwarded: ${retry.forwarded.length}`);
      } else {
        console.log(`Queued webhooks pulled: ${result.pulled}`);
        console.log(`Webhooks verified/forwarded: ${result.forwarded.length}`);
      }
    } finally {
      if (localServer.started && localServer.child) {
        try { localServer.child.kill('SIGTERM'); } catch {}
      }
    }
    return;
  }

  console.log('Polling for queued webhooks every 5 seconds...');
  while (true) {
    try {
      const result = await runOnce(token);
      if (result.refreshToken) {
        token = await getAccessToken();
        console.log('TrueLayer sandbox token refreshed.');
      } else if (result.pulled > 0) {
        console.log(`Queue cycle: pulled=${result.pulled} forwarded=${result.forwarded.length}`);
      }
    } catch (err) {
      console.error('Webhook router cycle:', err.message || err);
    }
    await new Promise(resolve => setTimeout(resolve, POLL_MS));
  }
}

if (require.main === module) {
  main().catch(err => {
    console.error('G-Bank sandbox webhook router: BLOCKED');
    console.error(err.message || err);
    process.exit(2);
  });
}

module.exports = {
  ROUTER_URL,
  DEFAULT_DESTINATION,
  requireSandboxSafety,
  destinationUrl,
  sanitizedForwardHeaders,
  getAccessToken,
  sleep,
  safeNetworkCause,
  transientHttpStatus,
  pullWebhooks,
  forwardWebhook,
  runOnce,
  localDestinationReachable,
  startLocalBankingServerIfNeeded
};
