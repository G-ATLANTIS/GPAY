const express = require('express');
const fs = require('fs');
const path = require('path');
const checkFraud = require('../utils/g-fraud');
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
    const mollieClient = getMollieClient();
    const publicBaseUrl = getPublicBaseUrl();
    const encodedOrderId = encodeURIComponent(orderId);

    const payment = await mollieClient.payments.create({
      amount: { currency: 'EUR', value: numericAmount.toFixed(2) },
      description: `Order ${orderId}`,
      redirectUrl: `${publicBaseUrl}/success/${encodedOrderId}`,
      webhookUrl: `${publicBaseUrl}/api/mollie/webhook`,
      metadata: { orderId, amount: numericAmount.toFixed(2), email },
      ...(method ? { method } : {}),
    });

    ensurePaymentLogDir();
    fs.appendFileSync(
      path.join(process.cwd(), 'logs', 'payments.log'),
      `[INIT] ${new Date().toISOString()} order=${orderId} provider=mollie payment=${payment.id}\n`
    );

    return res.json({
      provider: 'mollie',
      paymentId: payment.id,
      paymentUrl: payment.getCheckoutUrl(),
    });
  } catch (err) {
    if (err?.code === 'GPAY_CONFIG_MISSING' || err?.code === 'GPAY_INVALID_PUBLIC_URL') {
      return res.status(503).json({
        error: 'Payment provider unavailable',
        code: err.code,
      });
    }

    console.error('Mollie payment creation error:', err.message);
    return res.status(502).json({ error: 'Payment creation failed' });
  }
});

module.exports = router;
