'use strict';

const https = require('node:https');
const crypto = require('node:crypto');

// Low-level TrueLayer v3 provider I/O. Same style as providers/mollie-live.js:
// self-contained node:https, no axios, no framework. Contains ONLY provider
// transport + request signing. Policy / idempotency / audit / assurance live in
// the spine, not here.
//
// UNSAFE for direct use as a live-action path: reach it only through
// TrueLayerSpineConnector (enforced by scripts/ci/check-spine-bypass.js).

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

function endpoints(env) {
  const live = String((env || process.env).TRUELAYER_ENV || 'sandbox').toLowerCase() === 'live';
  return {
    live,
    authHost: live ? 'auth.truelayer.com' : 'auth.truelayer-sandbox.com',
    apiHost: live ? 'api.truelayer.com' : 'api.truelayer-sandbox.com',
    environment: live ? 'LIVE' : 'SANDBOX',
  };
}

function privateKeyPem(env = process.env) {
  if (env.TRUELAYER_PRIVATE_KEY_B64) {
    return Buffer.from(env.TRUELAYER_PRIVATE_KEY_B64, 'base64').toString('utf8');
  }
  if (env.TRUELAYER_PRIVATE_KEY_PEM) {
    return String(env.TRUELAYER_PRIVATE_KEY_PEM).replace(/\\n/g, '\n');
  }
  return '';
}

function request({ host, method, path, headers = {}, body, timeoutMs = 20000 }) {
  return new Promise((resolve, reject) => {
    const payload =
      body === undefined || body === null
        ? null
        : Buffer.isBuffer(body)
          ? body
          : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const req = https.request(
      {
        hostname: host,
        port: 443,
        method,
        path,
        timeout: timeoutMs,
        headers: {
          Accept: 'application/json',
          ...(payload ? { 'Content-Length': payload.length } : {}),
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let data = null;
          if (text) {
            try {
              data = JSON.parse(text);
            } catch {
              data = { raw: text.slice(0, 2048) };
            }
          }
          resolve({ status: res.statusCode, headers: res.headers, data });
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('truelayer_timeout')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// Detached ES512 JWS over: `${METHOD} ${path}\n${headerLines}${body}`.
function buildSigningPayload({ method, path, headers = {}, body = '' }) {
  let payload = `${String(method).toUpperCase()} ${path}\n`;
  for (const [name, value] of Object.entries(headers)) payload += `${name}: ${value}\n`;
  payload += body;
  return payload;
}

class TrueLayerLiveAdapter {
  constructor({ env = process.env, timeoutMs = 20000 } = {}) {
    this.name = 'truelayer-live';
    this.env = env;
    this.timeoutMs = timeoutMs;
    this._ep = endpoints(env);
  }

  assertConfigured() {
    const e = this.env;
    if (!e.TRUELAYER_CLIENT_ID || !e.TRUELAYER_CLIENT_SECRET) throw new Error('truelayer_client_credentials_missing');
    if (!e.TRUELAYER_SIGNING_KID) throw new Error('truelayer_signing_kid_missing');
    if (!privateKeyPem(e)) throw new Error('truelayer_private_key_missing');
  }

  signRequest({ method, path, body = '', idempotencyKey }) {
    if (!idempotencyKey) throw new Error('idempotency_key_required_for_signing');
    const headers = { 'Idempotency-Key': idempotencyKey };
    const joseHeader = {
      alg: 'ES512',
      kid: String(this.env.TRUELAYER_SIGNING_KID),
      tl_version: '2',
      tl_headers: Object.keys(headers).join(','),
    };
    const encodedHeader = b64url(JSON.stringify(joseHeader));
    const signingPayload = buildSigningPayload({ method, path, headers, body });
    const signingInput = `${encodedHeader}.${b64url(signingPayload)}`;
    const signature = crypto.sign('sha512', Buffer.from(signingInput, 'utf8'), {
      key: privateKeyPem(this.env),
      dsaEncoding: 'ieee-p1363', // detached JWS requires raw R||S (132 bytes for P-521)
    });
    if (signature.length !== 132) throw new Error('truelayer_es512_requires_p521_key');
    return `${encodedHeader}..${signature.toString('base64url')}`;
  }

  async getAccessToken() {
    this.assertConfigured();
    const params = new URLSearchParams();
    params.set('grant_type', 'client_credentials');
    params.set('client_id', String(this.env.TRUELAYER_CLIENT_ID));
    params.set('client_secret', String(this.env.TRUELAYER_CLIENT_SECRET));
    params.set('scope', 'payments');
    const res = await request({
      host: this._ep.authHost,
      method: 'POST',
      path: '/connect/token',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
      timeoutMs: this.timeoutMs,
    });
    if (res.status !== 200 || !res.data || !res.data.access_token) {
      const err = new Error('truelayer_token_request_failed');
      err.provider_http_status = res.status;
      err.oauth_error = res.data && res.data.error ? String(res.data.error) : null;
      throw err;
    }
    return { access_token: res.data.access_token, scope: res.data.scope || null, token_type: res.data.token_type || null };
  }

  // Non-mutating: POST /test-signature returns 204 iff auth + signature are
  // valid. Proves authenticated + signing capability without a side effect.
  async preflight() {
    this.assertConfigured();
    const token = (await this.getAccessToken()).access_token;
    const idempotencyKey = crypto.randomUUID();
    const path = '/test-signature';
    const body = JSON.stringify({ nonce: crypto.randomUUID() });
    const signature = this.signRequest({ method: 'POST', path, body, idempotencyKey });
    const res = await request({
      host: this._ep.apiHost,
      method: 'POST',
      path,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': idempotencyKey,
        'Tl-Signature': signature,
      },
      body,
      timeoutMs: this.timeoutMs,
    });
    return {
      provider: this.name,
      environment: this._ep.environment,
      authenticated: true,
      signature_accepted: res.status === 204,
      provider_http_status: res.status,
      payment_endpoint_called: false,
      value_moved: false,
    };
  }

  // body: fully-formed TrueLayer v3 /payments payload (built by the connector).
  async createPayment({ body, idempotencyKey }) {
    this.assertConfigured();
    const rawBody = typeof body === 'string' ? body : JSON.stringify(body);
    const token = (await this.getAccessToken()).access_token;
    const path = '/v3/payments';
    const signature = this.signRequest({ method: 'POST', path, body: rawBody, idempotencyKey });
    const res = await request({
      host: this._ep.apiHost,
      method: 'POST',
      path,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': idempotencyKey,
        'Tl-Signature': signature,
      },
      body: rawBody,
      timeoutMs: this.timeoutMs,
    });
    if (res.status < 200 || res.status >= 300) {
      const err = new Error('truelayer_create_payment_failed');
      err.provider_http_status = res.status;
      err.provider_detail = (res.data && (res.data.detail || res.data.title || res.data.error)) || null;
      throw err;
    }
    const p = res.data || {};
    return {
      provider: this.name,
      environment: this._ep.environment,
      provider_http_status: res.status,
      payment_id: p.id || null,
      status: p.status || null,
      authorization_url: (p.hosted_page && p.hosted_page.uri) || null,
      resource_token: p.resource_token || null,
      idempotent_replayed: String(res.headers['idempotent-replayed'] || res.headers['tl-idempotent-replayed'] || '').toLowerCase() === 'true',
    };
  }

  async getPayment(paymentId) {
    this.assertConfigured();
    if (!/^[0-9a-f-]{20,64}$/i.test(String(paymentId || ''))) throw new Error('truelayer_payment_id_invalid');
    const token = (await this.getAccessToken()).access_token;
    const res = await request({
      host: this._ep.apiHost,
      method: 'GET',
      path: `/v3/payments/${encodeURIComponent(paymentId)}`,
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json; charset=UTF-8' },
      timeoutMs: this.timeoutMs,
    });
    if (res.status !== 200) {
      const err = new Error('truelayer_payment_readback_failed');
      err.provider_http_status = res.status;
      throw err;
    }
    const p = res.data || {};
    const ben = (p.payment_method && p.payment_method.beneficiary) || {};
    return {
      provider: this.name,
      environment: this._ep.environment,
      payment_id: p.id || null,
      status: p.status || null,
      amount_in_minor: typeof p.amount_in_minor === 'number' ? p.amount_in_minor : null,
      currency: p.currency || null,
      beneficiary_iban: (ben.account_identifier && ben.account_identifier.iban) || null,
      beneficiary_reference: ben.reference || null,
      metadata: p.metadata || null,
      created_at: p.created_at || null,
      provider_http_status: 200,
    };
  }
}

module.exports = { TrueLayerLiveAdapter, endpoints, privateKeyPem, buildSigningPayload, sha256 };
