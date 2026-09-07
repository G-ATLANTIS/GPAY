const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

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
  const allowedBeneficiaryIbans = String(process.env.G_BANK_ALLOWED_BENEFICIARY_IBANS || '')
    .split(',')
    .map((value) => value.replace(/\s+/g, '').toUpperCase())
    .filter(Boolean);
  return {
    clientId: process.env.TRUELAYER_CLIENT_ID || '',
    clientSecret: process.env.TRUELAYER_CLIENT_SECRET || '',
    signingKid: process.env.TRUELAYER_SIGNING_KID || '',
    privateKey: privateKeyPem(),
    returnUri: process.env.TRUELAYER_RETURN_URI || '',
    maxEur,
    liveEnabled: process.env.G_BANK_ENABLE_LIVE === 'true',
    providerProbeEnabled: process.env.G_BANK_ENABLE_PROVIDER_PROBE === 'true',
    providerProbeSecret: process.env.G_BANK_PROVIDER_PROBE_SECRET || '',
    approvalSecret: process.env.G_BANK_APPROVAL_SECRET || '',
    secretRotationReceipt: process.env.G_BANK_SECRET_ROTATION_RECEIPT || '',
    sandboxVerificationReceipt: process.env.G_BANK_SANDBOX_VERIFICATION_RECEIPT || '',
    allowedBeneficiaryIbans
  };
}

function providerConfigStatus() {
  const cfg = requiredConfig();
  const missing = [];
  if (!cfg.clientId) missing.push('TRUELAYER_CLIENT_ID');
  if (!cfg.clientSecret) missing.push('TRUELAYER_CLIENT_SECRET');
  if (!cfg.signingKid) missing.push('TRUELAYER_SIGNING_KID');
  if (!cfg.privateKey) missing.push('TRUELAYER_PRIVATE_KEY_B64 or TRUELAYER_PRIVATE_KEY_PEM');

  return {
    provider: 'truelayer',
    environment: envMode(),
    configured: missing.length === 0,
    provider_probe_enabled: cfg.providerProbeEnabled,
    provider_probe_authorization_configured: Boolean(cfg.providerProbeSecret),
    missing
  };
}

function assertProviderConfigured() {
  const status = providerConfigStatus();
  if (!status.configured) {
    const err = new Error('TrueLayer provider authentication is fail-closed: required credentials/signing configuration is missing.');
    err.statusCode = 503;
    err.publicDetails = status;
    throw err;
  }
  return requiredConfig();
}

function assertProviderProbeEnabled(authorizationHeader) {
  const cfg = requiredConfig();
  if (!cfg.providerProbeEnabled) {
    const err = new Error('Provider readiness probe is disabled. Set G_BANK_ENABLE_PROVIDER_PROBE=true to allow a non-payment TrueLayer authentication/signature check.');
    err.statusCode = 403;
    err.publicDetails = {
      provider: 'truelayer',
      environment: envMode(),
      provider_probe_enabled: false,
      payment_created: false,
      value_moved: false
    };
    throw err;
  }

  if (cfg.providerProbeSecret.length < 32) {
    const err = new Error('Provider readiness probe authorization is not configured securely.');
    err.statusCode = 503;
    throw err;
  }

  const supplied = Buffer.from(String(authorizationHeader || ''), 'utf8');
  const expected = Buffer.from(cfg.providerProbeSecret, 'utf8');
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    const err = new Error('Provider readiness probe authorization failed.');
    err.statusCode = 403;
    throw err;
  }
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
  if (live && !cfg.approvalSecret) missing.push('G_BANK_APPROVAL_SECRET');
  if (live && !cfg.secretRotationReceipt) missing.push('G_BANK_SECRET_ROTATION_RECEIPT');
  if (live && !cfg.sandboxVerificationReceipt) missing.push('G_BANK_SANDBOX_VERIFICATION_RECEIPT');
  if (live && cfg.allowedBeneficiaryIbans.length === 0) missing.push('G_BANK_ALLOWED_BENEFICIARY_IBANS');

  return {
    provider: 'truelayer',
    environment: live ? 'live' : 'sandbox',
    provider_authentication: providerConfigStatus(),
    configured: missing.length === 0,
    missing,
    live_execution_enabled: live && cfg.liveEnabled,
    live_approval_required: live,
    live_approval_configured: live ? Boolean(cfg.approvalSecret) : false,
    historical_secret_rotation_receipt_present: Boolean(cfg.secretRotationReceipt),
    sandbox_verification_receipt_present: Boolean(cfg.sandboxVerificationReceipt),
    allowed_beneficiary_count: cfg.allowedBeneficiaryIbans.length,
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

function isValidIban(iban) {
  const compact = String(iban || '').replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(compact)) return false;

  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;

  for (const ch of rearranged) {
    const fragment = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of fragment) {
      remainder = (remainder * 10 + Number(digit)) % 97;
    }
  }

  return remainder === 1;
}

function approvalMessage({ idempotencyKey, amountInMinor, iban, reference }) {
  return [idempotencyKey, String(amountInMinor), iban, String(reference)].join('|');
}

function assertLiveApproval({ idempotencyKey, amountInMinor, iban, reference, approvalHeader }) {
  if (envMode() !== 'live') return;

  const cfg = assertConfigured();
  if (!cfg.allowedBeneficiaryIbans.includes(iban)) {
    throw Object.assign(new Error('Beneficiary is not present in the live G-Bank allowlist.'), { statusCode: 403 });
  }

  if (!idempotencyKey) {
    throw Object.assign(new Error('A caller-supplied Idempotency-Key is required for live payments.'), { statusCode: 400 });
  }

  const supplied = String(approvalHeader || '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) {
    throw Object.assign(new Error('Valid X-G-Bank-Approval is required for live payments.'), { statusCode: 403 });
  }

  const expected = crypto
    .createHmac('sha256', cfg.approvalSecret)
    .update(approvalMessage({ idempotencyKey, amountInMinor, iban, reference }))
    .digest('hex');

  const suppliedBuffer = Buffer.from(supplied, 'hex');
  const expectedBuffer = Buffer.from(expected, 'hex');
  if (suppliedBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)) {
    throw Object.assign(new Error('Live G-Bank approval did not match this payment intent.'), { statusCode: 403 });
  }
}

function assertPaymentInput(body) {
  const amountText = String(body?.amount_eur ?? '').trim();
  if (!/^\d+(?:\.\d{1,2})?$/.test(amountText)) {
    throw Object.assign(new Error('amount_eur must be a positive EUR amount with at most 2 decimals.'), { statusCode: 400 });
  }

  const normalizedAmountInMinor = Math.round(Number(amountText) * 100);
  if (!Number.isSafeInteger(normalizedAmountInMinor) || normalizedAmountInMinor <= 0) {
    throw Object.assign(new Error('amount_eur is outside the supported range.'), { statusCode: 400 });
  }
  const amountEur = normalizedAmountInMinor / 100;

  const cfg = requiredConfig();
  if (amountEur > cfg.maxEur) {
    throw Object.assign(new Error('Payment exceeds G_BANK_MAX_PAYMENT_EUR.'), { statusCode: 400 });
  }

  const beneficiary = body?.beneficiary || {};
  const user = body?.user || {};
  const address = user.address || {};

  const iban = String(beneficiary.iban || '').replace(/\s+/g, '').toUpperCase();
  if (!isValidIban(iban)) {
    throw Object.assign(new Error('beneficiary.iban is required and must pass IBAN checksum validation.'), { statusCode: 400 });
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

  return { amountEur, amountInMinor: normalizedAmountInMinor, beneficiary: { ...beneficiary, iban }, user: { ...user, address } };
}

async function getAccessToken(httpClient = axios) {
  const cfg = assertProviderConfigured();
  const { authBase } = endpoints();
  const params = new URLSearchParams();
  params.set('grant_type', 'client_credentials');
  params.set('client_id', cfg.clientId);
  params.set('client_secret', cfg.clientSecret);
  params.set('scope', 'payments');

  const response = await httpClient.post(`${authBase}/connect/token`, params.toString(), {
    timeout: 15000,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });

  if (!response.data?.access_token) throw new Error('TrueLayer token response did not contain access_token.');
  return response.data.access_token;
}

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function buildTrueLayerSigningPayload({ method, path, headers = {}, body = '' }) {
  const normalizedMethod = String(method || '').toUpperCase();
  if (!path || !String(path).startsWith('/')) {
    throw new Error('TrueLayer signing path must start with /.');
  }
  if (typeof body !== 'string') {
    throw new Error('TrueLayer signing body must be a string.');
  }

  let payload = `${normalizedMethod} ${path}\n`;
  for (const [name, value] of Object.entries(headers)) {
    payload += `${name}: ${value}\n`;
  }
  payload += body;
  return payload;
}

function signRequest({ method, path, body = '', idempotencyKey }) {
  const cfg = assertProviderConfigured();
  if (!idempotencyKey) {
    throw new Error('Idempotency-Key is required for TrueLayer request signing.');
  }

  const headers = { 'Idempotency-Key': idempotencyKey };
  const joseHeader = {
    alg: 'ES512',
    kid: cfg.signingKid,
    tl_version: '2',
    tl_headers: Object.keys(headers).join(',')
  };

  const encodedHeader = base64url(JSON.stringify(joseHeader));
  const signingPayload = buildTrueLayerSigningPayload({ method, path, headers, body });
  const encodedPayload = base64url(signingPayload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto.sign('sha512', Buffer.from(signingInput, 'utf8'), {
    key: cfg.privateKey,
    dsaEncoding: 'ieee-p1363'
  });

  if (signature.length !== 132) {
    throw new Error('TrueLayer ES512 signing requires a P-521 private key.');
  }

  return `${encodedHeader}..${signature.toString('base64url')}`;
}

async function performProviderReadiness(httpClient = axios, authorizationHeader = '') {
  assertProviderProbeEnabled(authorizationHeader);
  assertProviderConfigured();

  const path = '/test-signature';
  const nonce = crypto.randomUUID();
  const rawBody = JSON.stringify({ nonce });
  const idempotencyKey = crypto.randomUUID();
  const token = await getAccessToken(httpClient);
  const signature = signRequest({
    method: 'POST',
    path,
    body: rawBody,
    idempotencyKey
  });
  const { apiBase } = endpoints();

  const response = await httpClient.post(`${apiBase}${path}`, rawBody, {
    timeout: 15000,
    validateStatus: () => true,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Idempotency-Key': idempotencyKey,
      'Tl-Signature': signature
    }
  });

  const signatureValid = response.status === 204;

  return {
    provider: 'truelayer',
    environment: envMode(),
    access_token_obtained: true,
    request_signature_accepted: signatureValid,
    provider_http_status: response.status,
    payment_created: false,
    bank_authorization_started: false,
    value_moved: false,
    verified_write: false,
    verified_value_flow: false,
    execution_graph: {
      candidate_state: signatureValid ? 'AUTHENTICATED_TESTED' : 'AUTHENTICATION_OR_SIGNATURE_FAILED',
      verified_read: false,
      verified_write: false,
      verified_value_flow: false,
      reason: signatureValid
        ? 'TrueLayer accepted the non-payment signed readiness request. This proves provider authentication/signing only.'
        : 'TrueLayer did not return 204 for the non-payment signature test.'
    }
  };
}

function executionGraphStatus() {
  const cfg = requiredConfig();
  const provider = providerConfigStatus();
  const live = envMode() === 'live';

  const providerState = !provider.configured
    ? 'CREDENTIAL_REQUIRED'
    : cfg.providerProbeEnabled
      ? 'PROBE_ENABLED_NOT_YET_VERIFIED'
      : 'CONFIGURED_NOT_EXTERNALLY_VERIFIED';

  const liveReleaseEvidencePresent =
    Boolean(cfg.secretRotationReceipt) &&
    Boolean(cfg.sandboxVerificationReceipt);

  return {
    graph: 'G_REAL_EXECUTION_GRAPH',
    provider: 'truelayer',
    environment: envMode(),
    edges: {
      provider_authentication: {
        class: 'VERIFIED_READ_CANDIDATE',
        state: providerState,
        active: false,
        reason: 'Local configuration is not external provider proof. Promote only after a successful non-payment provider readiness receipt.'
      },
      payment_creation: {
        class: 'VERIFIED_WRITE_CANDIDATE',
        state: 'BLOCKED_UNTIL_EXPLICIT_PAYMENT_INTENT',
        active: false,
        reason: 'Payment creation requires an explicit request and does not follow from provider readiness.'
      },
      value_flow: {
        class: 'VERIFIED_VALUE_FLOW',
        state: 'BLOCKED',
        active: false,
        reason: 'Requires explicit bank authorization, bank execution evidence and independent settlement/receipt evidence.'
      }
    },
    release_gates: {
      live_environment_selected: live,
      live_enable_flag: cfg.liveEnabled,
      historical_secret_rotation_receipt_present: Boolean(cfg.secretRotationReceipt),
      sandbox_verification_receipt_present: Boolean(cfg.sandboxVerificationReceipt),
      live_release_evidence_present: liveReleaseEvidencePresent,
      beneficiary_allowlist_configured: cfg.allowedBeneficiaryIbans.length > 0,
      transaction_approval_secret_configured: Boolean(cfg.approvalSecret)
    },
    verified_value_flow: false
  };
}

router.get('/health', (req, res) => {
  res.json({
    ...configStatus(),
    bank_authorization_required: true,
    verified_value_flow: false
  });
});

router.get('/graph-status', (req, res) => {
  res.json(executionGraphStatus());
});


router.post('/provider-readiness', async (req, res) => {
  try {
    const result = await performProviderReadiness(
      axios,
      req.get('X-G-Bank-Probe-Authorization') || ''
    );
    res.status(result.request_signature_accepted ? 200 : 502).json(result);
  } catch (err) {
    const status = err.statusCode || err.response?.status || 500;
    res.status(status).json({
      error: err.message || 'TrueLayer provider readiness check failed.',
      details: err.publicDetails || err.response?.data || undefined,
      payment_created: false,
      value_moved: false,
      verified_value_flow: false
    });
  }
});

router.post('/create-payment', async (req, res) => {
  try {
    assertConfigured();
    const { amountEur, amountInMinor, beneficiary, user } = assertPaymentInput(req.body);
    const path = '/v3/payments';
    const callerIdempotencyKey = req.get('Idempotency-Key');
    const idempotencyKey = callerIdempotencyKey || crypto.randomUUID();

    assertLiveApproval({
      idempotencyKey: callerIdempotencyKey,
      amountInMinor,
      iban: beneficiary.iban,
      reference: beneficiary.reference,
      approvalHeader: req.get('X-G-Bank-Approval')
    });

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
      hosted_page: {
        return_uri: requiredConfig().returnUri,
        country_code: 'NL',
        language_code: 'nl'
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
      authorization_url: payment.hosted_page?.uri || null,
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
      creditor_settlement_proven: false,
      verified_value_flow: false,
      value_flow_state: executed
        ? 'BANK_ACCEPTED_NOT_SETTLEMENT_PROVEN'
        : failed
          ? 'FAILED'
          : 'PENDING_AUTHORIZATION_OR_EXECUTION',
      execution_graph: {
        edge: 'VERIFIED_VALUE_FLOW_CANDIDATE',
        active: false,
        reason: executed
          ? 'The bank accepted the external-account payment, but creditor settlement is not proven by TrueLayer executed status alone.'
          : failed
            ? 'Payment failed; value-flow edge remains inactive.'
            : 'Awaiting end-user bank authorization and execution confirmation.'
      },
      executed_at: payment.executed_at || null
    });
  } catch (err) {
    const status = err.statusCode || err.response?.status || 500;
    res.status(status).json({
      error: err.message || 'Open Banking payment status check failed.',
      details: err.publicDetails || err.response?.data || undefined
    });
  }
});

router._test = {
  envMode,
  providerConfigStatus,
  configStatus,
  assertProviderProbeEnabled,
  isValidIban,
  approvalMessage,
  assertPaymentInput,
  assertLiveApproval,
  buildTrueLayerSigningPayload,
  signRequest,
  getAccessToken,
  performProviderReadiness,
  executionGraphStatus
};

module.exports = router;
