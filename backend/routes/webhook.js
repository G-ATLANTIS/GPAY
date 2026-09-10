const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const rewardTokens = require('../utils/g-token-reward');
const generateInvoice = require('../utils/invoice-generator');
const sendMail = require('../utils/mailer');
const { createReceipt } = require('../utils/payment-receipt');
const { getProcessed, recordProcessed } = require('../utils/payment-idempotency-store');
const { acquirePaymentLock } = require('../utils/payment-lock');
const { createGcoinSettlementIntent } = require('../utils/gcoin-settlement-intent');
const router = express.Router();

function requireMollieConfig() {
  const apiKey = process.env.MOLLIE_API_KEY;
  if (!apiKey || !apiKey.trim()) {
    const err = new Error('MOLLIE_API_KEY is required');
    err.code = 'CONFIG_ERROR';
    throw err;
  }
  return apiKey.trim();
}

function getMollieClient() {
  const apiKey = requireMollieConfig();
  return require('@mollie/api-client').default({ apiKey });
}

router.post('/mollie/webhook', async (req, res) => {
  const id = typeof req.body?.id === 'string' ? req.body.id.trim() : '';
  if (!id) return res.status(400).json({ error: 'Missing payment id' });

  let lock;
  try {
    const mollieClient = getMollieClient();

    lock = acquirePaymentLock('mollie', id);
    if (!lock.acquired) {
      return res.status(202).json({ status: 'processing', providerPaymentId: id });
    }

    const alreadyProcessed = getProcessed('mollie', id);
    if (alreadyProcessed) {
      return res.status(200).json({
        status: 'already_processed',
        providerPaymentId: id,
        receiptHash: alreadyProcessed.receiptHash,
        settlementEventId: alreadyProcessed.settlementEventId || null,
        settlementExecutionStatus: alreadyProcessed.settlementExecutionStatus || null,
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
    const currency = payment.amount?.currency || 'EUR';
    const rewardEventId = crypto
      .createHash('sha256')
      .update(`mollie:${id}:${orderId}:reward`)
      .digest('hex');

    // This computes the current reward amount only. It does not transfer tokens.
    const tokens = rewardTokens(amount, email, { eventId: rewardEventId });

    // Bind the verified payment to canonical GCOIN metadata without signing/broadcasting.
    const settlementIntent = createGcoinSettlementIntent({
      provider: 'mollie',
      providerPaymentId: id,
      orderId,
      amount: String(amount),
      currency,
      rewardEventId,
      gcoinAmount: String(tokens),
      broadcast: false,
    });

    // Invoice resolves only after the PDF is durably written.
    const invoicePath = await generateInvoice(orderId, amount, email);

    const receipt = createReceipt({
      provider: 'mollie',
      providerPaymentId: id,
      orderId,
      amount: String(amount),
      currency,
      status: payment.status,
      processedAt,
      rewardEventId,
      tokens,
      settlementEventId: settlementIntent.settlementEventId,
      settlementMode: settlementIntent.mode,
      settlementExecutionStatus: settlementIntent.executionStatus,
      settlementContractAddress: settlementIntent.contractAddress,
      settlementChainId: settlementIntent.chainId,
    });

    // Commit local processing before best-effort notification. No blockchain execution occurs here.
    const result = recordProcessed('mollie', id, receipt);
    if (!result.created) {
      return res.status(200).json({
        status: 'already_processed',
        providerPaymentId: id,
        receiptHash: result.record.receiptHash,
        settlementEventId: result.record.settlementEventId || null,
        settlementExecutionStatus: result.record.settlementExecutionStatus || null,
      });
    }

    fs.mkdirSync('logs', { recursive: true });
    fs.appendFileSync(
      'logs/payments.log',
      `[OK] ${orderId} provider=mollie payment=${id} status=paid receipt=${receipt.receiptHash} gcoin_intent=${settlementIntent.settlementEventId} execution=not_attempted\n`
    );

    let notification = 'sent';
    try {
      await sendMail(email, invoicePath);
    } catch (mailErr) {
      notification = 'failed';
      console.error('Payment confirmation email failed:', mailErr.message);
    }

    return res.status(200).json({
      status: 'processed',
      providerPaymentId: id,
      receiptHash: receipt.receiptHash,
      settlementEventId: settlementIntent.settlementEventId,
      settlementMode: settlementIntent.mode,
      settlementExecutionStatus: settlementIntent.executionStatus,
      notification,
    });
  } catch (err) {
    if (err.code === 'CONFIG_ERROR') {
      return res.status(503).json({ error: err.message });
    }
    if (err.code === 'GCOIN_BROADCAST_DENIED') {
      return res.status(403).json({ error: err.message });
    }
    console.error('Mollie webhook error:', err.message);
    return res.status(500).json({ error: 'Webhook processing failed' });
  } finally {
    if (lock?.acquired) lock.release();
  }
});

module.exports = router;
