const express = require('express');
const fs = require('fs');
const mollieClient = require('@mollie/api-client').default({ apiKey: process.env.MOLLIE_API_KEY });
const rewardTokens = require('../utils/g-token-reward');
const generateInvoice = require('../utils/invoice-generator');
const sendMail = require('../utils/mailer');
const router = express.Router();

router.post('/mollie/webhook', async (req, res) => {
  const id = req.body.id;
  try {
    const payment = await mollieClient.payments.get(id);
    const { orderId, amount, email } = payment.metadata;
    if (payment.status === 'paid') {
      const tokens = rewardTokens(amount, email);
      const invoicePath = generateInvoice(orderId, amount, email);
      await sendMail(email, invoicePath);
      fs.appendFileSync('logs/payments.log', `[OK] ${orderId} betaalstatus: paid\n`);
    }
    res.status(200).send('OK');
  } catch (err) {
    res.status(500).send('Error');
  }
});
