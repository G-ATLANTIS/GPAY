const express = require('express');
const axios = require('axios');
const router = express.Router();

const PULSEPAY_API_URL = 'https://api.pulsepay.io/v1';
const PULSEPAY_API_KEY = process.env.PULSEPAY_API_KEY || 'YOUR_API_KEY';

// G-BANK-CANONICAL-LIVE-ROUTING-P0
// PulsePay has no spine connector and is not part of the G-Bank canonical
// path. Its create-payment endpoint is a direct un-spined provider mutation, so
// it is DENY by default. It cannot be re-enabled without an explicit,
// deliberate environment opt-in acknowledging the bypass.
function assertUnspinedProviderExplicitlyAccepted() {
  if (process.env.G_BANK_ALLOW_UNSPINED_PULSEPAY !== 'I_ACCEPT_UNSPINED_EXECUTION') {
    const err = new Error(
      'PulsePay create-payment is disabled: direct un-spined provider execution is DENY. ' +
        'Route it through executeVerified() or set G_BANK_ALLOW_UNSPINED_PULSEPAY=I_ACCEPT_UNSPINED_EXECUTION.',
    );
    err.statusCode = 403;
    throw err;
  }
}

router.post('/create-payment', async (req, res) => {
  const { amount, currency, userId } = req.body;
  try {
    assertUnspinedProviderExplicitlyAccepted();
    const response = await axios.post(
      `${PULSEPAY_API_URL}/payments`,
      { amount, currency, userId },
      { headers: { 'Authorization': `Bearer ${PULSEPAY_API_KEY}` } }
    );
    res.json(response.data);
  } catch (error) {
    console.error('PulsePay API error:', error.response?.data || error.message);
    res.status(error.statusCode || 500).json({ error: error.statusCode ? error.message : 'Payment creation failed' });
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
