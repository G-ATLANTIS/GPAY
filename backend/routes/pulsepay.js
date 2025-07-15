const express = require('express');
const axios = require('axios');
const router = express.Router();

const PULSEPAY_API_URL = 'https://api.pulsepay.io/v1';
const PULSEPAY_API_KEY = process.env.PULSEPAY_API_KEY || 'YOUR_API_KEY';

router.post('/create-payment', async (req, res) => {
  const { amount, currency, userId } = req.body;
  try {
    const response = await axios.post(
      `${PULSEPAY_API_URL}/payments`,
      { amount, currency, userId },
      { headers: { 'Authorization': `Bearer ${PULSEPAY_API_KEY}` } }
    );
    res.json(response.data);
  } catch (error) {
    console.error('PulsePay API error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Payment creation failed' });
  }
});

router.get('/payment-status/:paymentId', async (req, res) => {
  const { paymentId } = req.params;
  try {
    const response = await axios.get(
      `${PULSEPAY_API_URL}/payments/${paymentId}`,
      { headers: { 'Authorization': `Bearer ${PULSEPAY_API_KEY}` } }
    );
    res.json(response.data);
  } catch (error) {
    console.error('PulsePay API error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Payment status retrieval failed' });
  }
});

module.exports = router;
