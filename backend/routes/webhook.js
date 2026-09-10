const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const mollieClient = require('@mollie/api-client').default({ apiKey: process.env.MOLLIE_API_KEY });
const rewardTokens = require('../utils/g-token-reward');
const generateInvoice = require('../utils/invoice-generator');
const sendMail = require('../utils/mailer');
const { createReceipt } = require('../utils/payment-receipt');
const { getProcessed, recordProcessed } = require('../utils/payment-idempotency-store');
const { acquirePaymentLock } = require('../utils/payment-lock');
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

  let lock;
  try {
    requireMollieConfig();

    lock = acquirePaymentLock('mollie', id);
    if (!lock.acquired) {
      return res.status(202).json({
        status: 'processing',
        providerPaymentId: id,
      });
    }

    const alreadyProcessed = getProcessed('mollie', id);
    if (alreadyProcessed) {
      return res.status(200).json({
        status: 'already_processed',
        providerPaymentId: id,
        receiptHash: alreadyProcessed.receiptHash,
      });
    }

    // Never trust callback body for canonical payment state; re-read it from Mollie.
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

    // Current rewardTokens is a deterministic calculation/log, not an external token transfer.
    const tokens = rewardTokens(amount, email, { eventId: rewardEventId });

    // Invoice generation is deterministic for orderId and resolves only after the PDF is durable.
    const invoicePath = await generateInvoice(orderId, amount, email);

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

    // Commit financial processing before best-effort notification. Duplicate callbacks stop here.
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

    let notification = 'sent';
    try {
      await sendMail(email, invoicePath);
    } catch (mailErr) {
      // Notification is deliberately non-transactional: payment processing stays committed.
      notification = 'failed';
      console.error('Payment confirmation email failed:', mailErr.message);
    }

    return res.status(200).json({
      status: 'processed',
      providerPaymentId: id,
      receiptHash: receipt.receiptHash,
      notification,
    });
  } catch (err) {
    if (err.code === 'CONFIG_ERROR') {
      return res.status(503).json({ error: err.message });
    }
    console.error('Mollie webhook error:', err.message);
    return res.status(500).json({ error: 'Webhook processing failed' });
  } finally {
    if (lock?.acquired) lock.release();
  }
});

module.exports = router;
