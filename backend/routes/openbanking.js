const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const tlSigning = require('truelayer-signing');

const router = express.Router();

function envMode() {
  return (process.env.TRUELAYER_ENV || 'sandbox').toLowerCase() === 'live' ? 'live' : 'sandbox';
}

function endpoints() {
  const live = envMode() === 'live';
  return {
    live,
    authBase: live ? 'https://auth.truelayer.com' : 'https://auth.truelayer-sandbox.com',
    apiBase: live ? 'https://api.truelayer.com' : 'https://api.truelayer-sandbox.com',
    hppBase: live ? 'https://payment.truelayer.com/payments' : 'https://payment.truelayer-sandbox.com/payments'
  };
}

function privateKeyPem() {
  if (process.env.TRUELAYER_PRIVATE_KEY_B64) {
    return Buffer.from(process.env.TRUELAYER_PRIVATE_KEY_B64, 'base64').toString('utf8');
  }
  if (process.env.TRUELAYER_PRIVATE_KEY_PEM) {
    return process.env.TRUELAYER_PRIVATE_KEY_PEM.replace(/\\n/g, '\n');
  }
  return '';
}

function requiredConfig() {
  const maxEur = Number(process.env.G_BANK_MAX_PAYMENT_EUR || (envMode() === 'sandbox' ? '100' : '0'));
  return {
    clientId: process.env.TRUELAYER_CLIENT_ID || '',
    clientSecret: process.env.TRUELAYER_CLIENT_SECRET || '',
    signingKid: process.env.TRUELAYER_SIGNING_KID || '',
    privateKey: privateKeyPem(),
    returnUri: process.env.TRUELAYER_RETURN_URI || '',
    maxEur,
    liveEnabled: process.env.G_BANK_ENABLE_LIVE === 'true'
  };
}

function configStatus() {
  const cfg = requiredConfig();
  const { live } = endpoints();
  const missing = [];
  if (!cfg.clientId) missing.push('TRUELAYER_CLIENT_ID');
  if (!cfg.clientSecret) missing.push('TRUELAYER_CLIENT_SECRET');
  if (!cfg.signingKid) missing.push('TRUELAYER_SIGNING_KID');
  if (!cfg.privateKey) missing.push('TRUELAYER_PRIVATE_KEY_B64 or TRUELAYER_PRIVATE_KEY_PEM');
  if (!cfg.returnUri) missing.push('TRUELAYER_RETURN_URI');
  if (!Number.isFinite(cfg.maxEur) || cfg.maxEur <= 0) missing.push('G_BANK_MAX_PAYMENT_EUR');
  if (live && !cfg.liveEnabled) missing.push('G_BANK_ENABLE_LIVE=true');

  return {
    provider: 'truelayer',
    environment: live ? 'live' : 'sandbox',
    configured: missing.length === 0,
    missing,
    live_execution_enabled: live && cfg.liveEnabled,
    max_payment_eur: Number.isFinite(cfg.maxEur) ? cfg.maxEur : 0
  };
}

function assertConfigured() {
  const status = configStatus();
  if (!status.configured) {
    const err = new Error('Open Banking is fail-closed: required configuration is missing.');
    err.statusCode = 503;
    err.publicDetails = status;
    throw err;
  }
  return requiredConfig();
}

function assertPaymentInput(body) {
  const amountEur = Number(body?.amount_eur);
  if (!Number.isFinite(amountEur) || amountEur <= 0 || Math.round(amountEur * 100) !== amountEur * 100) {
    throw Object.assign(new Error('amount_eur must be a positive EUR amount with at most 2 decimals.'), { statusCode: 400 });
  }

  const cfg = requiredConfig();
  if (amountEur > cfg.maxEur) {
    throw Object.assign(new Error('Payment exceeds G_BANK_MAX_PAYMENT_EUR.'), { statusCode: 400 });
  }

  const beneficiary = body?.beneficiary || {};
  const user = body?.user || {};
  const address = user.address || {};

  const iban = String(beneficiary.iban || '').replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}[0-9A-Z]{13,32}$/.test(iban)) {
    throw Object.assign(new Error('beneficiary.iban is required and must be a valid-looking IBAN.'), { statusCode: 400 });
  }
  if (!beneficiary.name || !beneficiary.reference) {
    throw Object.assign(new Error('beneficiary.name and beneficiary.reference are required.'), { statusCode: 400 });
  }

  const requiredUser = ['name', 'email', 'phone', 'date_of_birth'];
  for (const key of requiredUser) {
    if (!user[key]) throw Object.assign(new Error(`user.${key} is required.`), { statusCode: 400 });
  }

  for (const key of ['address_line1', 'city', 'zip', 'country_code']) {
    if (!address[key]) throw Object.assign(new Error(`user.address.${key} is required.`), { statusCode: 400 });
  }

  return { amountEur, beneficiary: { ...beneficiary, iban }, user: { ...user, address } };
}

async function getAccessToken() {
  const cfg = assertConfigured();
  const { authBase } = endpoints();
  const params = new URLSearchParams();
  params.set('grant_type', 'client_credentials');
  params.set('client_id', cfg.clientId);
  params.set('client_secret', cfg.clientSecret);
  params.set('scope', 'payments');

  const response = await axios.post(`${authBase}/connect/token`, params.toString(), {
    timeout: 15000,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });

  if (!response.data?.access_token) throw new Error('TrueLayer token response did not contain access_token.');
  return response.data.access_token;
}

function signRequest({ method, path, body = '', idempotencyKey }) {
  const cfg = assertConfigured();
  const headers = idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {};
  return tlSigning.sign({
    kid: cfg.signingKid,
    privateKeyPem: cfg.privateKey,
    method,
    path,
    headers,
    body
  });
}

function hppUrl(paymentId, resourceToken) {
  const cfg = assertConfigured();
  const { hppBase } = endpoints();
  const hash = new URLSearchParams({
    payment_id: paymentId,
    resource_token: resourceToken,
    return_uri: cfg.returnUri
  });
  return `${hppBase}?lng=nl#${hash.toString()}`;
}

router.get('/health', (req, res) => {
  res.json({
    ...configStatus(),
    bank_authorization_required: true,
    verified_value_flow: false
  });
});

router.post('/create-payment', async (req, res) => {
  try {
    assertConfigured();
    const { amountEur, beneficiary, user } = assertPaymentInput(req.body);
    const amountInMinor = Math.round(amountEur * 100);
    const path = '/v3/payments';
    const idempotencyKey = req.get('Idempotency-Key') || crypto.randomUUID();

    const payload = {
      amount_in_minor: amountInMinor,
      currency: 'EUR',
      payment_method: {
        type: 'bank_transfer',
        provider_selection: {
          type: 'user_selected',
          filter: {
            countries: ['NL'],
            customer_segments: ['retail']
          },
          scheme_selection: {
            type: 'user_selected',
            allow_remitter_fee: false
          }
        },
        beneficiary: {
          type: 'external_account',
          account_holder_name: String(beneficiary.name),
          account_identifier: {
            type: 'iban',
            iban: beneficiary.iban
          },
          reference: String(beneficiary.reference).slice(0, 18)
        }
      },
      user: {
        name: String(user.name),
        email: String(user.email),
        phone: String(user.phone),
        date_of_birth: String(user.date_of_birth),
        address: {
          address_line1: String(user.address.address_line1),
          ...(user.address.address_line2 ? { address_line2: String(user.address.address_line2) } : {}),
          city: String(user.address.city),
          ...(user.address.state ? { state: String(user.address.state) } : {}),
          zip: String(user.address.zip),
          country_code: String(user.address.country_code).toUpperCase()
        }
      },
      metadata: {
        g_bank: 'true',
        execution_graph_edge: 'VERIFIED_VALUE_FLOW_CANDIDATE'
      }
    };

    const rawBody = JSON.stringify(payload);
    const token = await getAccessToken();
    const signature = signRequest({ method: 'POST', path, body: rawBody, idempotencyKey });
    const { apiBase } = endpoints();

    const response = await axios.post(`${apiBase}${path}`, rawBody, {
      timeout: 20000,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': idempotencyKey,
        'Tl-Signature': signature
      }
    });

    const payment = response.data || {};
    res.status(201).json({
      provider: 'truelayer',
      environment: envMode(),
      payment_id: payment.id,
      status: payment.status,
      authorization_required: true,
      authorization_url: payment.id && payment.resource_token ? hppUrl(payment.id, payment.resource_token) : null,
      idempotency_key: idempotencyKey,
      execution_graph: {
        edge: 'VERIFIED_VALUE_FLOW_CANDIDATE',
        active: false,
        reason: 'End-user bank authorization and external execution confirmation still required.'
      }
    });
  } catch (err) {
    const status = err.statusCode || err.response?.status || 500;
    res.status(status).json({
      error: err.message || 'Open Banking payment creation failed.',
      details: err.publicDetails || err.response?.data || undefined
    });
  }
});

router.get('/payment/:paymentId', async (req, res) => {
  try {
    assertConfigured();
    const paymentId = String(req.params.paymentId || '');
    if (!/^[0-9a-f-]{36}$/i.test(paymentId)) {
      return res.status(400).json({ error: 'Invalid payment ID.' });
    }

    const path = `/v3/payments/${paymentId}`;
    const idempotencyKey = crypto.randomUUID();
    const token = await getAccessToken();
    const signature = signRequest({ method: 'GET', path, body: '', idempotencyKey });
    const { apiBase } = endpoints();

    const response = await axios.get(`${apiBase}${path}`, {
      timeout: 15000,
      headers: {
        Authorization: `Bearer ${token}`,
        'Idempotency-Key': idempotencyKey,
        'Tl-Signature': signature
      }
    });

    const payment = response.data || {};
    const status = String(payment.status || '');
    const executed = status === 'executed' || status === 'payment_executed';
    const failed = status === 'failed' || status === 'payment_failed';

    res.json({
      provider: 'truelayer',
      payment_id: payment.id || paymentId,
      status,
      failed,
      bank_accepted_execution: executed,
      verified_value_flow: executed,
      execution_graph: {
        edge: 'VERIFIED_VALUE_FLOW',
        active: executed,
        reason: executed
          ? 'External-account payment reached TrueLayer executed terminal state; bank accepted the submitted payment.'
          : failed
            ? 'Payment failed; value-flow edge remains inactive.'
            : 'Awaiting bank authorization/execution confirmation.'
      },
      provider_response: payment
    });
  } catch (err) {
    const status = err.statusCode || err.response?.status || 500;
    res.status(status).json({
      error: err.message || 'Open Banking payment status check failed.',
      details: err.publicDetails || err.response?.data || undefined
    });
  }
});

module.exports = router;
