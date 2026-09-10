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
const { createPaymentStateRuntime } = require('../utils/payment-state-runtime');
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
    const stateRuntime = createPaymentStateRuntime();
    await stateRuntime.ensureReady();

    lock = acquirePaymentLock('mollie', id);
    if (!lock.acquired) return res.status(202).json({ status: 'processing', providerPaymentId: id });

    const alreadyProcessed = getProcessed('mollie', id);
    if (alreadyProcessed) {
      return res.status(200).json({
        status: 'already_processed', providerPaymentId: id,
        receiptHash: alreadyProcessed.receiptHash,
        settlementEventId: alreadyProcessed.settlementEventId || null,
        settlementExecutionStatus: alreadyProcessed.settlementExecutionStatus || null,
      });
    }

    const begun = await stateRuntime.begin('mollie', id);
    const payment = await mollieClient.payments.get(id);
    const { orderId, amount, email } = payment.metadata || {};

    if (!orderId || !amount || !email) return res.status(422).json({ error: 'Payment metadata incomplete' });
    if (payment.status !== 'paid') {
      return res.status(200).json({ status: payment.status, providerPaymentId: id, processed: false });
    }

    const processedAt = begun.state.processedAt;
    const currency = payment.amount?.currency || 'EUR';
    await stateRuntime.advance('mollie', id, 'PROVIDER_VERIFIED', { orderId, amount: String(amount), currency });

    const rewardEventId = crypto.createHash('sha256').update(`mollie:${id}:${orderId}:reward`).digest('hex');
    const tokens = rewardTokens(amount, email, { eventId: rewardEventId });
    const settlementIntent = createGcoinSettlementIntent({
      provider: 'mollie', providerPaymentId: id, orderId,
      amount: String(amount), currency, rewardEventId,
      gcoinAmount: String(tokens), broadcast: false,
    });

    const invoicePath = await generateInvoice(orderId, amount, email);
    const receipt = createReceipt({
      provider: 'mollie', providerPaymentId: id, orderId,
      amount: String(amount), currency, status: payment.status, processedAt,
      rewardEventId, tokens,
      settlementEventId: settlementIntent.settlementEventId,
      settlementMode: settlementIntent.mode,
      settlementExecutionStatus: settlementIntent.executionStatus,
      settlementContractAddress: settlementIntent.contractAddress,
      settlementChainId: settlementIntent.chainId,
    });

    await stateRuntime.advance('mollie', id, 'EFFECTS_PREPARED', {
      receiptHash: receipt.receiptHash,
      settlementEventId: settlementIntent.settlementEventId,
    });

    const result = recordProcessed('mollie', id, receipt);
    if (!result.created) {
      return res.status(200).json({
        status: 'already_processed', providerPaymentId: id,
        receiptHash: result.record.receiptHash,
        settlementEventId: result.record.settlementEventId || null,
        settlementExecutionStatus: result.record.settlementExecutionStatus || null,
      });
    }

    await stateRuntime.advance('mollie', id, 'COMMITTED', { receiptHash: receipt.receiptHash });

    fs.mkdirSync('logs', { recursive: true });
    fs.appendFileSync('logs/payments.log', `[OK] ${orderId} provider=mollie payment=${id} status=paid receipt=${receipt.receiptHash} gcoin_intent=${settlementIntent.settlementEventId} execution=not_attempted\n`);

    let notification = 'sent';
    try { await sendMail(email, invoicePath); }
    catch (mailErr) {
      notification = 'failed';
      console.error('Payment confirmation email failed:', mailErr.message);
    }

    return res.status(200).json({
      status: 'processed', providerPaymentId: id,
      receiptHash: receipt.receiptHash,
      settlementEventId: settlementIntent.settlementEventId,
      settlementMode: settlementIntent.mode,
      settlementExecutionStatus: settlementIntent.executionStatus,
      notification,
    });
  } catch (err) {
    if (err.code === 'CONFIG_ERROR' || err.code === 'PAYMENT_STATE_CONFIG_MISSING' || err.code === 'PAYMENT_STATE_DRIVER_MISSING') {
      return res.status(503).json({ error: err.message, code: err.code });
    }
    if (err.code === 'PAYMENT_STATE_CAS_CONFLICT') {
      return res.status(409).json({ error: 'Payment state contention', code: err.code });
    }
    if (err.code === 'GCOIN_BROADCAST_DENIED') return res.status(403).json({ error: err.message });
    console.error('Mollie webhook error:', err.message);
    return res.status(500).json({ error: 'Webhook processing failed' });
  } finally {
    if (lock?.acquired) lock.release();
  }
});

module.exports = router;
