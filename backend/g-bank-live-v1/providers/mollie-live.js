'use strict';

const https = require('node:https');
const crypto = require('node:crypto');

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function requestJson({ method, path, apiKey, body, headers = {}, timeoutMs = 10000 }) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const req = https.request({
      hostname: 'api.mollie.com',
      port: 443,
      method,
      path,
      timeout: timeoutMs,
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: 'application/hal+json',
        ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}),
        ...headers,
      },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let data = null;
        if (text) {
          try { data = JSON.parse(text); } catch { data = { raw: text.slice(0, 2048) }; }
        }
        resolve({ status: res.statusCode, headers: res.headers, data });
      });
    });
    req.on('timeout', () => req.destroy(new Error('mollie_timeout')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

class MollieLiveAdapter {
  constructor({ apiKey = process.env.MOLLIE_API_KEY, timeoutMs = 10000 } = {}) {
    this.name = 'mollie-live';
    this.apiKey = String(apiKey || '');
    this.timeoutMs = timeoutMs;
  }

  assertConfigured() {
    if (!this.apiKey.startsWith('live_') || this.apiKey.length < 20) {
      throw new Error('mollie_live_api_key_required');
    }
  }

  async preflight() {
    this.assertConfigured();
    const response = await requestJson({
      method: 'GET',
      path: '/v2/methods?sequenceType=oneoff',
      apiKey: this.apiKey,
      timeoutMs: this.timeoutMs,
    });
    if (response.status !== 200) {
      const err = new Error('mollie_live_preflight_failed');
      err.provider_http_status = response.status;
      err.provider_detail = response.data?.detail || response.data?.title || null;
      throw err;
    }
    const methods = response.data?._embedded?.methods || [];
    return {
      provider: this.name,
      environment: 'LIVE',
      authenticated: true,
      enabled_methods: methods.map(m => m.id).filter(Boolean),
      provider_http_status: 200,
      payment_endpoint_called: false,
      value_moved: false,
    };
  }

  async createPayment({ intent, idempotencyKey }) {
    this.assertConfigured();
    if (!intent.redirect_url || !intent.webhook_url) throw new Error('mollie_redirect_and_webhook_required');
    const body = {
      amount: { currency: intent.currency, value: (intent.amount_minor / 100).toFixed(2) },
      description: intent.description,
      redirectUrl: intent.redirect_url,
      webhookUrl: intent.webhook_url,
      metadata: {
        ...intent.metadata,
        g_intent_id: intent.intent_id,
        g_intent_sha256: intent.intent_sha256,
        g_destination_binding_sha256: sha256(intent.destination_binding),
      },
    };
    const response = await requestJson({
      method: 'POST',
      path: '/v2/payments',
      apiKey: this.apiKey,
      body,
      timeoutMs: this.timeoutMs,
      headers: { 'Idempotency-Key': idempotencyKey },
    });
    if (response.status < 200 || response.status >= 300) {
      const err = new Error('mollie_create_payment_failed');
      err.provider_http_status = response.status;
      err.provider_detail = response.data?.detail || response.data?.title || null;
      throw err;
    }
    return {
      provider: this.name,
      environment: 'LIVE',
      provider_http_status: response.status,
      payment_id: response.data?.id,
      status: response.data?.status,
      checkout_url: response.data?._links?.checkout?.href || null,
      mode: response.data?.mode || null,
      idempotent_replayed: String(response.headers['idempotent-replayed'] || '').toLowerCase() === 'true',
    };
  }

  async getPayment(paymentId) {
    this.assertConfigured();
    if (!/^tr_[A-Za-z0-9]+$/.test(String(paymentId || ''))) throw new Error('mollie_payment_id_invalid');
    const response = await requestJson({
      method: 'GET',
      path: `/v2/payments/${encodeURIComponent(paymentId)}`,
      apiKey: this.apiKey,
      timeoutMs: this.timeoutMs,
    });
    if (response.status !== 200) {
      const err = new Error('mollie_payment_readback_failed');
      err.provider_http_status = response.status;
      throw err;
    }
    return {
      provider: this.name,
      payment_id: response.data?.id,
      status: response.data?.status,
      mode: response.data?.mode,
      amount: response.data?.amount || null,
      metadata: response.data?.metadata || null,
      provider_http_status: 200,
    };
  }
}

module.exports = { MollieLiveAdapter, requestJson };
