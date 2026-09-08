require('dotenv').config();

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

async function pullWebhooks(token, fetchFn = fetch) {
  const response = await fetchFn(ROUTER_URL, {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(30000)
  });
  if (response.status === 401) return { unauthorized: true, webhooks: [] };
  if (!response.ok) {
    throw new Error(`TrueLayer webhook pull failed with HTTP ${response.status}.`);
  }
  const body = await response.json();
  if (!body || !Array.isArray(body.webhooks)) {
    throw new Error('TrueLayer webhook router returned an invalid payload.');
  }
  return { unauthorized: false, webhooks: body.webhooks };
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
  if (pulled.unauthorized) return { refreshToken: true, forwarded: [] };
  const forwarded = [];
  for (const webhook of pulled.webhooks) {
    forwarded.push(await forwardWebhook(webhook, fetchFn));
  }
  return { refreshToken: false, forwarded };
}

async function main() {
  requireSandboxSafety();
  console.log('G-Bank native TrueLayer sandbox webhook router');
  console.log('Pull:', ROUTER_URL);
  console.log('Forward:', destinationUrl());
  console.log('Live banking: DISABLED');
  console.log('Credentials: loaded from .env (not command-line arguments)');

  let token = await getAccessToken();
  console.log('TrueLayer sandbox token: OK');
  console.log('Polling for queued webhooks every 5 seconds...');

  while (true) {
    try {
      const result = await runOnce(token);
      if (result.refreshToken) {
        token = await getAccessToken();
        console.log('TrueLayer sandbox token refreshed.');
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
  pullWebhooks,
  forwardWebhook,
  runOnce
};
