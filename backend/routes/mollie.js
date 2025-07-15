const express = require('express');
const fs = require('fs');
const mollieClient = require('@mollie/api-client').default({ apiKey: process.env.MOLLIE_API_KEY });
const rewardTokens = require('../utils/g-token-reward');
const generateInvoice = require('../utils/invoice-generator');
const sendMail = require('../utils/mailer');
const checkFraud = require('../utils/g-fraud');
const router = express.Router();

router.post('/create-payment', async (req, res) => {
  const { amount, orderId, email, method } = req.body;
  const fraud = checkFraud(req.ip, amount, req.headers['user-agent']);
  if (fraud) return res.status(403).send('Fraudeverdacht');

  try {
    const payment = await mollieClient.payments.create({
      amount: { currency: 'EUR', value: amount },
      description: `Order ${orderId}`,
      redirectUrl: `http://localhost:5173/success/${orderId}`,
      webhookUrl: 'http://localhost:4000/api/mollie/webhook',
      metadata: { orderId, amount, email }
    });

    fs.appendFileSync('logs/payments.log', `[INIT] ${orderId} ${payment.id}\n`);
    res.json({ paymentUrl: payment.getCheckoutUrl() });

  } catch (err) {
    res.status(500).json({ error: 'Betaling mislukt' });
  }
});
