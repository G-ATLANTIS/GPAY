const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const mollieClient = require('@mollie/api-client').default({ apiKey: process.env.MOLLIE_API_KEY });
const rewardTokens = require('../utils/g-token-reward');
const generateInvoice = require('../utils/invoice-generator');
const sendMail = require('../utils/mailer');
const { createReceipt } = require('../utils/payment-receipt');
const { getProcessed, recordProcessed } = require('../utils/payment-idempotency-store');
const router = express.Router();

function requireMollieConfig() {
  if (!process.env.MOLLIE_API_KEY) {
    const err = new Error('MOLLIE_API_KEY is required');
    err.code = 'CONFIG_ERROR';
    throw err;
  }
}

router.post('/mollie/webhook', async (req, res) => {
  const id = typeof req.body?.id === 'string' ? req.body.id.trim() : '';
  if (!id) return res.status(400).json({ error: 'Missing payment id' });

  try {
    requireMollieConfig();

    const alreadyProcessed = getProcessed('mollie', id);
    if (alreadyProcessed) {
      return res.status(200).json({
        status: 'already_processed',
        providerPaymentId: id,
        receiptHash: alreadyProcessed.receiptHash,
      });
    }

    // Do not trust callback body for payment state. Re-read canonical state from Mollie.
    const payment = await mollieClient.payments.get(id);
    const { orderId, amount, email } = payment.metadata || {};

    if (!orderId || !amount || !email) {
      return res.status(422).json({ error: 'Payment metadata incomplete' });
    }

    if (payment.status !== 'paid') {
      return res.status(200).json({
        status: payment.status,
        providerPaymentId: id,
        processed: false,
      });
    }

    const processedAt = new Date().toISOString();
    const rewardEventId = crypto
      .createHash('sha256')
      .update(`mollie:${id}:${orderId}:reward`)
      .digest('hex');

    const tokens = rewardTokens(amount, email, { eventId: rewardEventId });
    const invoicePath = generateInvoice(orderId, amount, email);
    await sendMail(email, invoicePath);

    const receipt = createReceipt({
      provider: 'mollie',
      providerPaymentId: id,
      orderId,
      amount: String(amount),
      currency: payment.amount?.currency || 'EUR',
      status: payment.status,
      processedAt,
      rewardEventId,
      tokens,
    });

    const result = recordProcessed('mollie', id, receipt);
    if (!result.created) {
      return res.status(200).json({
        status: 'already_processed',
        providerPaymentId: id,
        receiptHash: result.record.receiptHash,
      });
    }

    fs.mkdirSync('logs', { recursive: true });
    fs.appendFileSync(
      'logs/payments.log',
      `[OK] ${orderId} provider=mollie payment=${id} status=paid receipt=${receipt.receiptHash}\n`
    );

    return res.status(200).json({
      status: 'processed',
      providerPaymentId: id,
      receiptHash: receipt.receiptHash,
    });
  } catch (err) {
    if (err.code === 'CONFIG_ERROR') {
      return res.status(503).json({ error: err.message });
    }
    console.error('Mollie webhook error:', err.message);
    return res.status(500).json({ error: 'Webhook processing failed' });
  }
});

module.exports = router;
