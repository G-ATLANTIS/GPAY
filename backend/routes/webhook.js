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
const { createPaymentIntentRuntime } = require('../utils/payment-intent-runtime');
const { createPaymentEffectLedger } = require('../utils/payment-effect-ledger');
const { prepareVerifiedPaymentTransaction } = require('../utils/payment-postgres-transaction');
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

function effectData(record) {
  return record?.data || {};
}

function postgresMode() {
  return String(process.env.GPAY_PAYMENT_STATE_BACKEND || 'local').trim().toLowerCase() === 'postgres';
}

router.post('/mollie/webhook', async (req, res) => {
  const id = typeof req.body?.id === 'string' ? req.body.id.trim() : '';
  if (!id) return res.status(400).json({ error: 'Missing payment id' });

  let lock;
  try {
    const mollieClient = getMollieClient();
    const stateRuntime = createPaymentStateRuntime();
    const intentRuntime = createPaymentIntentRuntime();
    const effectLedger = createPaymentEffectLedger();
    await Promise.all([
      stateRuntime.ensureReady(),
      intentRuntime.ensureReady(),
      effectLedger.ensureReady(),
    ]);

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

    const payment = await mollieClient.payments.get(id);
    const { gpayIntentId, orderId, amount, email } = payment.metadata || {};
    const providerAmount = payment.amount?.value;
    const currency = payment.amount?.currency || 'EUR';

    if (!gpayIntentId || !orderId || !amount || !email) {
      return res.status(422).json({ error: 'Payment metadata incomplete' });
    }

    if (!providerAmount || Number(providerAmount).toFixed(2) !== Number(amount).toFixed(2)) {
      return res.status(422).json({ error: 'Provider amount does not match payment metadata', code: 'PAYMENT_AMOUNT_MISMATCH' });
    }

    const intentVerification = await intentRuntime.verify({
      intentId: gpayIntentId,
      providerPaymentId: id,
      orderId,
      amount: providerAmount,
      currency,
      email,
    });
    if (!intentVerification.ok) {
      return res.status(403).json({
        error: 'Payment is not bound to a valid GPAY intent',
        code: 'PAYMENT_INTENT_VERIFICATION_FAILED',
        reason: intentVerification.reason,
      });
    }

    if (payment.status !== 'paid') {
      return res.status(200).json({ status: payment.status, providerPaymentId: id, processed: false });
    }

    let processedAt;
    const rewardEventId = crypto.createHash('sha256').update(`mollie:${id}:${orderId}:reward`).digest('hex');

    if (postgresMode()) {
      const pool = stateRuntime?.adapter?.pool;
      if (!pool) {
        const err = new Error('PostgreSQL payment state runtime did not expose a pool for atomic preparation');
        err.code = 'PAYMENT_TX_POOL_REQUIRED';
        throw err;
      }
      const txResult = await prepareVerifiedPaymentTransaction({
        pool,
        provider: 'mollie',
        providerPaymentId: id,
        intentId: gpayIntentId,
        orderId,
        amount: providerAmount,
        currency,
        email,
        effectData: {
          reward: { orderId, rewardEventId },
          invoice: { orderId },
          'gcoin-intent': { orderId, rewardEventId },
        },
      });
      processedAt = txResult.state.processedAt;
    } else {
      const begun = await stateRuntime.begin('mollie', id);
      processedAt = begun.state.processedAt;
      await stateRuntime.advance('mollie', id, 'PROVIDER_VERIFIED', {
        gpayIntentId,
        orderId,
        amount: String(providerAmount),
        currency,
      });
    }

    const rewardPrepared = await effectLedger.prepare('mollie', id, 'reward', {
      gpayIntentId,
      orderId,
      rewardEventId,
    });
    let tokens = effectData(rewardPrepared.record).tokens;
    if (rewardPrepared.record.status !== 'COMPLETED' || tokens == null) {
      tokens = rewardTokens(providerAmount, email, { eventId: rewardEventId });
      await effectLedger.complete('mollie', id, 'reward', { tokens: String(tokens), rewardEventId });
    }

    const settlementIntent = createGcoinSettlementIntent({
      provider: 'mollie', providerPaymentId: id, orderId,
      amount: String(providerAmount), currency, rewardEventId,
      gcoinAmount: String(tokens), broadcast: false,
    });
    const gcoinPrepared = await effectLedger.prepare('mollie', id, 'gcoin-intent', {
      gpayIntentId,
      settlementEventId: settlementIntent.settlementEventId,
    });
    if (gcoinPrepared.record.status !== 'COMPLETED') {
      await effectLedger.complete('mollie', id, 'gcoin-intent', {
        settlementEventId: settlementIntent.settlementEventId,
        executionStatus: settlementIntent.executionStatus,
        broadcast: false,
      });
    }

    const invoicePrepared = await effectLedger.prepare('mollie', id, 'invoice', {
      gpayIntentId,
      orderId,
    });
    let invoicePath = effectData(invoicePrepared.record).invoicePath;
    if (invoicePrepared.record.status !== 'COMPLETED' || !invoicePath) {
      invoicePath = await generateInvoice(orderId, providerAmount, email);
      await effectLedger.complete('mollie', id, 'invoice', { invoicePath });
    }

    const receipt = createReceipt({
      provider: 'mollie', providerPaymentId: id, orderId,
      amount: String(providerAmount), currency, status: payment.status, processedAt,
      rewardEventId, tokens,
      settlementEventId: settlementIntent.settlementEventId,
      settlementMode: settlementIntent.mode,
      settlementExecutionStatus: settlementIntent.executionStatus,
      settlementContractAddress: settlementIntent.contractAddress,
      settlementChainId: settlementIntent.chainId,
    });

    await stateRuntime.advance('mollie', id, 'EFFECTS_PREPARED', {
      gpayIntentId,
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

    await stateRuntime.advance('mollie', id, 'COMMITTED', {
      gpayIntentId,
      receiptHash: receipt.receiptHash,
    });

    fs.mkdirSync('logs', { recursive: true });
    fs.appendFileSync('logs/payments.log', `[OK] ${orderId} provider=mollie payment=${id} intent=${gpayIntentId} status=paid receipt=${receipt.receiptHash} gcoin_intent=${settlementIntent.settlementEventId} execution=not_attempted\n`);

    const emailPrepared = await effectLedger.prepare('mollie', id, 'email', {
      gpayIntentId,
      invoicePath,
    });
    let notification = emailPrepared.record.status === 'COMPLETED' ? 'already_sent' : 'sent';
    if (emailPrepared.record.status !== 'COMPLETED') {
      try {
        await sendMail(email, invoicePath);
        await effectLedger.complete('mollie', id, 'email', { sentAt: new Date().toISOString() });
      } catch (mailErr) {
        notification = 'failed';
        console.error('Payment confirmation email failed:', mailErr.message);
      }
    }

    return res.status(200).json({
      status: 'processed', providerPaymentId: id,
      paymentIntentId: gpayIntentId,
      receiptHash: receipt.receiptHash,
      settlementEventId: settlementIntent.settlementEventId,
      settlementMode: settlementIntent.mode,
      settlementExecutionStatus: settlementIntent.executionStatus,
      notification,
    });
  } catch (err) {
    if (
      err.code === 'CONFIG_ERROR' ||
      err.code === 'PAYMENT_STATE_CONFIG_MISSING' ||
      err.code === 'PAYMENT_STATE_DRIVER_MISSING' ||
      err.code === 'PAYMENT_EFFECT_CONFIG_MISSING' ||
      err.code === 'PAYMENT_EFFECT_DRIVER_MISSING' ||
      err.code === 'PAYMENT_TX_POOL_REQUIRED'
    ) {
      return res.status(503).json({ error: err.message, code: err.code });
    }
    if (
      err.code === 'PAYMENT_STATE_CAS_CONFLICT' ||
      err.code === 'PAYMENT_INTENT_BIND_CONFLICT' ||
      err.code === 'PAYMENT_EFFECT_CONFLICT'
    ) {
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
