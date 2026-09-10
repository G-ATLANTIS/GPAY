const express = require('express');
const axios = require('axios');
const router = express.Router();

const PULSEPAY_API_URL = process.env.PULSEPAY_API_URL || 'https://api.pulsepay.io/v1';

function requirePulsePayApiKey() {
  const apiKey = process.env.PULSEPAY_API_KEY;
  if (!apiKey || !apiKey.trim()) {
    const error = new Error('PULSEPAY_API_KEY is required');
    error.code = 'PULSEPAY_CONFIG_MISSING';
    throw error;
  }
  return apiKey.trim();
}

function providerErrorResponse(res, error, operation) {
  if (error?.code === 'PULSEPAY_CONFIG_MISSING') {
    return res.status(503).json({
      error: 'Payment provider unavailable',
      code: error.code,
    });
  }

  console.error(`PulsePay ${operation} error:`, error.response?.data || error.message);
  return res.status(502).json({ error: `Payment ${operation} failed` });
}

router.post('/create-payment', async (req, res) => {
  const { amount, currency, userId } = req.body;

  if (amount == null || !currency || !userId) {
    return res.status(400).json({
      error: 'amount, currency and userId are required',
    });
  }

  try {
    const apiKey = requirePulsePayApiKey();
    const response = await axios.post(
      `${PULSEPAY_API_URL}/payments`,
      { amount, currency, userId },
      {
        headers: { Authorization: `Bearer ${apiKey}` },
        timeout: 10000,
      }
    );
    return res.json(response.data);
  } catch (error) {
    return providerErrorResponse(res, error, 'creation');
  }
});

router.get('/payment-status/:paymentId', async (req, res) => {
  const { paymentId } = req.params;

  if (!paymentId) {
    return res.status(400).json({ error: 'paymentId is required' });
  }

  try {
    const apiKey = requirePulsePayApiKey();
    const response = await axios.get(
      `${PULSEPAY_API_URL}/payments/${encodeURIComponent(paymentId)}`,
      {
        headers: { Authorization: `Bearer ${apiKey}` },
        timeout: 10000,
      }
    );
    return res.json(response.data);
  } catch (error) {
    return providerErrorResponse(res, error, 'status retrieval');
  }
});

module.exports = router;
