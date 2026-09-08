require('dotenv').config();

const crypto = require('node:crypto');
const axios = require('axios');

const openBankingRoutes = require('../backend/routes/openbanking');
const webhookRouter = require('./route-banking-sandbox-webhooks');
const smoke = require('./run-banking-sandbox-smoke');

const {
  envMode,
  signRequest,
  getAccessToken,
  recordPaymentCreated
} = openBankingRoutes._test;

const API_BASE = 'https://api.truelayer-sandbox.com';
const AUTH_BASE = 'https://auth.truelayer-sandbox.com';
const MOCK_BASE = 'https://pay-mock-connect.truelayer-sandbox.com';
const PROVIDER_ID = 'mock-payments-gb-redirect';
const SCHEME_ID = 'faster_payments_service';

function requireSandboxSafety() {
  webhookRouter.requireSandboxSafety();
  if (envMode() !== 'sandbox') {
    throw new Error('Provider webhook generator is sandbox-only.');
  }
  if (process.env.G_BANK_ENABLE_LIVE === 'true') {
    throw new Error('Provider webhook generator refuses to run while G_BANK_ENABLE_LIVE=true.');
  }
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function beneficiaryInput() {
  return {
    name: 'John doe',
    sortCode: '000000',
    accountNumber: '12345678',
    reference: '(LegacyReturn)'
  };
}

function buildPaymentPayload() {
  const beneficiary = beneficiaryInput();
  return {
    amount_in_minor: 15,
    currency: 'GBP',
    payment_method: {
      type: 'bank_transfer',
      provider_selection: {
        type: 'preselected',
        provider_id: PROVIDER_ID,
        scheme_id: SCHEME_ID
      },
      beneficiary: {
        type: 'external_account',
        account_holder_name: beneficiary.name,
        account_identifier: {
          type: 'sort_code_account_number',
          sort_code: beneficiary.sortCode,
          account_number: beneficiary.accountNumber
        },
        reference: beneficiary.reference
      }
    },
    user: {
      name: 'john doe',
      email: 'a@a.com'
    }
  };
}

function parseMockAuthorizationUri(uri) {
  const parsed = new URL(String(uri || ''));
  if (parsed.protocol !== 'https:' || parsed.hostname !== 'pay-mock-connect.truelayer-sandbox.com') {
    throw new Error('Unexpected TrueLayer mock authorization host.');
  }
  const parts = parsed.pathname.split('/').filter(Boolean);
  const mockPaymentId = parts.at(-1) || '';
  if (!/^[0-9a-f-]{36}$/i.test(mockPaymentId)) {
    throw new Error('Mock authorization URI did not contain a valid payment id.');
  }
  const fragment = new URLSearchParams(parsed.hash.replace(/^#/, ''));
  const token = fragment.get('token') || '';
  if (!token) throw new Error('Mock authorization URI did not contain a token.');
  return { mockPaymentId, token };
}

function publicPaymentArtifact(payment, authorizationUri) {
  return {
    provider: 'truelayer',
    environment: 'sandbox',
    payment_id: String(payment.id || '').toLowerCase(),
    status: String(payment.status || ''),
    authorization_required: true,
    authorization_mode: 'direct_mock',
    authorization_flow_uri_sha256: sha256(authorizationUri),
    provider_id: PROVIDER_ID,
    scheme_id: SCHEME_ID,
    payment_created: true,
    value_moved: false,
    verified_value_flow: false
  };
}

async function signedPost(path, body, token, httpClient = axios) {
  const rawBody = JSON.stringify(body);
  const idempotencyKey = crypto.randomUUID();
  const signature = signRequest({
    method: 'POST',
    path,
    body: rawBody,
    idempotencyKey
  });
  const response = await httpClient.post(`${API_BASE}${path}`, rawBody, {
    timeout: 20000,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Idempotency-Key': idempotencyKey,
      'Tl-Signature': signature
    }
  });
  return { response, idempotencyKey, rawBody };
}

async function createDirectSandboxPayment(httpClient = axios) {
  requireSandboxSafety();
  const payload = buildPaymentPayload();
  const rawBody = JSON.stringify(payload);
  const idempotencyKey = crypto.randomUUID();
  const token = await getAccessToken(httpClient, { authBase: AUTH_BASE });
  const signature = signRequest({
    method: 'POST',
    path: '/v3/payments',
    body: rawBody,
    idempotencyKey
  });

  const response = await httpClient.post(`${API_BASE}/v3/payments`, rawBody, {
    timeout: 20000,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Idempotency-Key': idempotencyKey,
      'Tl-Signature': signature
    }
  });

  const payment = response.data || {};
  recordPaymentCreated({
    idempotencyKey,
    payment,
    rawBody,
    environment: 'sandbox'
  });

  if (!/^[0-9a-f-]{36}$/i.test(String(payment.id || ''))) {
    throw new Error('TrueLayer did not return a valid sandbox payment id.');
  }

  return {
    token,
    payment,
    requestBodySha256: sha256(rawBody)
  };
}

async function startDirectAuthorization(paymentId, token, httpClient = axios) {
  const path = `/v3/payments/${paymentId}/authorization-flow`;
  const body = {
    provider_selection: {},
    redirect: {
      return_uri: 'http://localhost:3000/callback'
    }
  };
  const { response } = await signedPost(path, body, token, httpClient);
  const next = response.data?.authorization_flow?.actions?.next;
  if (response.data?.status !== 'authorizing' || next?.type !== 'redirect' || !next.uri) {
    throw new Error('TrueLayer direct authorization flow did not return the expected redirect action.');
  }
  return String(next.uri);
}

async function executeMockPayment(authorizationUri, httpClient = axios) {
  const { mockPaymentId, token } = parseMockAuthorizationUri(authorizationUri);
  const response = await httpClient.post(
    `${MOCK_BASE}/api/single-immediate-payments/${mockPaymentId}/action`,
    { action: 'Execute', redirect: false },
    {
      timeout: 20000,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    }
  );
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`TrueLayer mock Execute failed with HTTP ${response.status}.`);
  }
  return { mockPaymentId };
}

async function waitForMatchingWebhook(paymentId, attempts = 20) {
  let token = await webhookRouter.getAccessToken();
  for (let i = 1; i <= attempts; i += 1) {
    let result = await webhookRouter.runOnce(token);
    if (result.refreshToken) {
      token = await webhookRouter.getAccessToken();
      result = await webhookRouter.runOnce(token);
    }
    const matching = result.forwarded.find(
      item => String(item.paymentId || '').toLowerCase() === String(paymentId).toLowerCase()
    );
    if (matching) return matching;
    if (i < attempts) await new Promise(resolve => setTimeout(resolve, 1500));
  }
  throw new Error('No matching TrueLayer sandbox webhook arrived through the provider webhook router.');
}

async function run() {
  requireSandboxSafety();
  const localServer = await webhookRouter.startLocalBankingServerIfNeeded();
  try {
    console.log('G-Bank provider-signed sandbox webhook E2E');
    console.log('Live banking: DISABLED');
    console.log('Provider:', PROVIDER_ID);
    console.log('Amount: GBP 0.15 (TrueLayer official webhook-generator fixture)');
    console.log('Secrets/tokens: not logged');

    const created = await createDirectSandboxPayment();
    const paymentId = String(created.payment.id).toLowerCase();
    console.log('Sandbox payment created:', paymentId);

    const authorizationUri = await startDirectAuthorization(paymentId, created.token);
    const artifact = smoke.writeJsonArtifact(
      `payment-created-${paymentId}`,
      publicPaymentArtifact(created.payment, authorizationUri)
    );
    console.log('Payment artifact:', artifact);

    await executeMockPayment(authorizationUri);
    console.log('TrueLayer mock provider action: Execute submitted.');

    const webhook = await waitForMatchingWebhook(paymentId);
    console.log(
      `Matching webhook verified/forwarded: type=${webhook.type} payment_id=${webhook.paymentId}`
    );

    await smoke.status(paymentId);
    await smoke.reconcile(paymentId);

    console.log('Provider-signed sandbox webhook E2E: VERIFIED');
    console.log('Payment ID:', paymentId);
    console.log('Verified value flow: FALSE');
    return paymentId;
  } finally {
    if (localServer.started && localServer.child) {
      try { localServer.child.kill('SIGTERM'); } catch {}
    }
  }
}

if (require.main === module) {
  run().catch(err => {
    console.error('Provider-signed sandbox webhook E2E: BLOCKED');
    console.error(err.message || err);
    if (err.response?.data) {
      const safe = JSON.stringify(err.response.data);
      console.error(safe.slice(0, 800));
    }
    process.exit(2);
  });
}

module.exports = {
  API_BASE,
  AUTH_BASE,
  MOCK_BASE,
  PROVIDER_ID,
  SCHEME_ID,
  requireSandboxSafety,
  beneficiaryInput,
  buildPaymentPayload,
  parseMockAuthorizationUri,
  publicPaymentArtifact,
  signedPost,
  createDirectSandboxPayment,
  startDirectAuthorization,
  executeMockPayment,
  waitForMatchingWebhook,
  run
};
