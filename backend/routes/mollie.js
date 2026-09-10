const express = require('express');
const fs = require('fs');
const path = require('path');
const checkFraud = require('../utils/g-fraud');
const { createMolliePaymentWithEvidence } = require('../utils/provider-evidence-client');
const { createPaymentIntentRuntime } = require('../utils/payment-intent-runtime');
const router = express.Router();

function requireEnv(name) {
  const value = process.env[name];
  if (!value || !value.trim()) {
    const error = new Error(`${name} is required`);
    error.code = 'GPAY_CONFIG_MISSING';
    throw error;
  }
  return value.trim();
}

function getMollieClient() {
  const apiKey = requireEnv('MOLLIE_API_KEY');
  return require('@mollie/api-client').default({ apiKey });
}

function getPublicBaseUrl() {
  const baseUrl = requireEnv('GPAY_PUBLIC_BASE_URL').replace(/\/$/, '');
  if (!/^https:\/\//i.test(baseUrl)) {
    const error = new Error('GPAY_PUBLIC_BASE_URL must use HTTPS');
    error.code = 'GPAY_INVALID_PUBLIC_URL';
    throw error;
  }
  return baseUrl;
}

function ensurePaymentLogDir() {
  fs.mkdirSync(path.join(process.cwd(), 'logs'), { recursive: true });
}

function appendEvidence(evidence) {
  ensurePaymentLogDir();
  const evidenceLogPath = path.join(process.cwd(), 'logs', 'provider-evidence.log');
  fs.appendFileSync(evidenceLogPath, `${JSON.stringify({ ts: new Date().toISOString(), ...evidence })}\n`);
}

router.post('/create-payment', async (req, res) => {
  const { amount, orderId, email, method } = req.body;

  if (!amount || !orderId || !email) {
    return res.status(400).json({ error: 'amount, orderId and email are required' });
  }

  const numericAmount = Number(amount);
  if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
    return res.status(400).json({ error: 'amount must be a positive number' });
  }

  const fraud = checkFraud(req.ip, amount, req.headers['user-agent']);
  if (fraud) return res.status(403).json({ error: 'Transaction rejected by fraud policy' });

  try {
    const publicBaseUrl = getPublicBaseUrl();
    const intentRuntime = createPaymentIntentRuntime();
    await intentRuntime.ensureReady();
    const encodedOrderId = encodeURIComponent(orderId);
    const canonicalAmount = numericAmount.toFixed(2);
    const intent = await intentRuntime.create({
      orderId,
      amount: canonicalAmount,
      currency: 'EUR',
      email,
    });

    const paymentRequest = {
      amount: { currency: 'EUR', value: canonicalAmount },
      description: `Order ${orderId}`,
      redirectUrl: `${publicBaseUrl}/success/${encodedOrderId}`,
      webhookUrl: `${publicBaseUrl}/api/mollie/webhook`,
      metadata: {
        gpayIntentId: intent.intentId,
        orderId,
        amount: canonicalAmount,
        email,
      },
      ...(method ? { method } : {}),
    };

    let payment;
    let providerEvidence = null;
    if (process.env.G_MOLLIE_EVIDENCE_CLIENT === 'true') {
      const apiKey = requireEnv('MOLLIE_API_KEY');
      const result = await createMolliePaymentWithEvidence(paymentRequest, { apiKey });
      payment = result.payment;
      providerEvidence = result.evidence;
      appendEvidence({
        provider: providerEvidence.provider,
        provider_scope: providerEvidence.provider_scope,
        http_status: providerEvidence.http_status,
        explicit_success: providerEvidence.explicit_success,
        provider_request_id: providerEvidence.provider_request_id,
        provider_request_id_source: providerEvidence.provider_request_id_source,
        provider_request_id_exposed: providerEvidence.provider_request_id_exposed,
        idempotency_key: providerEvidence.idempotency_key,
        production_binding_verified: providerEvidence.production_binding_verified,
        payment_id: payment.id || null,
        gpay_intent_id: intent.intentId,
      });
    } else {
      const mollieClient = getMollieClient();
      payment = await mollieClient.payments.create(paymentRequest);
    }

    if (!payment?.id) throw new Error('Mollie payment id missing');
    await intentRuntime.bind(intent.intentId, payment.id);

    const checkoutUrl = payment.getCheckoutUrl ? payment.getCheckoutUrl() : payment?._links?.checkout?.href;
    if (!checkoutUrl) throw new Error('Mollie checkout URL missing');

    ensurePaymentLogDir();
    fs.appendFileSync(
      path.join(process.cwd(), 'logs', 'payments.log'),
      `[INIT] ${new Date().toISOString()} order=${orderId} provider=mollie payment=${payment.id} intent=${intent.intentId}\n`
    );

    return res.json({
      provider: 'mollie',
      paymentId: payment.id,
      paymentIntentId: intent.intentId,
      paymentUrl: checkoutUrl,
      ...(providerEvidence ? {
        providerRequestId: providerEvidence.provider_request_id,
        evidenceCaptured: true,
      } : {}),
    });
  } catch (err) {
    if (err?.providerEvidence) {
      appendEvidence({
        provider: err.providerEvidence.provider,
        provider_scope: err.providerEvidence.provider_scope,
        http_status: err.providerEvidence.http_status,
        explicit_success: false,
        provider_request_id: err.providerEvidence.provider_request_id,
        provider_request_id_source: err.providerEvidence.provider_request_id_source,
        provider_request_id_exposed: err.providerEvidence.provider_request_id_exposed,
        idempotency_key: err.providerEvidence.idempotency_key,
        production_binding_verified: false,
        error_type: err.name || 'Error',
      });
    }

    if (
      err?.code === 'GPAY_CONFIG_MISSING' ||
      err?.code === 'GPAY_INVALID_PUBLIC_URL' ||
      err?.code === 'PAYMENT_STATE_CONFIG_MISSING' ||
      err?.code === 'PAYMENT_STATE_DRIVER_MISSING'
    ) {
      return res.status(503).json({ error: 'Payment provider unavailable', code: err.code });
    }

    if (err?.code?.startsWith('PAYMENT_INTENT_')) {
      return res.status(err.code === 'PAYMENT_INTENT_BIND_CONFLICT' ? 409 : 503).json({
        error: 'Payment intent persistence unavailable',
        code: err.code,
      });
    }

    console.error('Mollie payment creation error:', err.message);
    return res.status(502).json({ error: 'Payment creation failed' });
  }
});

module.exports = router;
