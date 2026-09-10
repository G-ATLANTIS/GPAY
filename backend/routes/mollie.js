const express = require('express');
const fs = require('fs');
const path = require('path');
const mollieClient = require('@mollie/api-client').default({ apiKey: process.env.MOLLIE_API_KEY });
const { createMolliePaymentWithEvidence } = require('../utils/provider-evidence-client');
const rewardTokens = require('../utils/g-token-reward');
const generateInvoice = require('../utils/invoice-generator');
const sendMail = require('../utils/mailer');
const checkFraud = require('../utils/g-fraud');
const router = express.Router();

const evidenceLogPath = path.join(__dirname, '..', 'logs', 'provider-evidence.log');

function appendEvidence(evidence) {
  fs.appendFileSync(evidenceLogPath, `${JSON.stringify({ ts: new Date().toISOString(), ...evidence })}\n`);
}

router.post('/create-payment', async (req, res) => {
  const { amount, orderId, email, method } = req.body;
  const fraud = checkFraud(req.ip, amount, req.headers['user-agent']);
  if (fraud) return res.status(403).send('Fraudeverdacht');

  const paymentRequest = {
    amount: { currency: 'EUR', value: amount },
    description: `Order ${orderId}`,
    redirectUrl: `http://localhost:5173/success/${orderId}`,
    webhookUrl: 'http://localhost:4000/api/mollie/webhook',
    metadata: { orderId, amount, email }
  };
  if (method) paymentRequest.method = method;

  try {
    let payment;
    if (process.env.G_MOLLIE_EVIDENCE_CLIENT === 'true') {
      const result = await createMolliePaymentWithEvidence(paymentRequest);
      payment = result.payment;
      appendEvidence({
        provider: result.evidence.provider,
        provider_scope: result.evidence.provider_scope,
        http_status: result.evidence.http_status,
        explicit_success: result.evidence.explicit_success,
        provider_request_id: result.evidence.provider_request_id,
        provider_request_id_source: result.evidence.provider_request_id_source,
        provider_request_id_exposed: result.evidence.provider_request_id_exposed,
        idempotency_key: result.evidence.idempotency_key,
        production_binding_verified: result.evidence.production_binding_verified,
        payment_id: payment.id || null
      });
    } else {
      payment = await mollieClient.payments.create(paymentRequest);
    }

    fs.appendFileSync(path.join(__dirname, '..', 'logs', 'payments.log'), `[INIT] ${orderId} ${payment.id}\n`);
    const checkoutUrl = payment.getCheckoutUrl ? payment.getCheckoutUrl() : payment?._links?.checkout?.href;
    if (!checkoutUrl) throw new Error('Mollie checkout URL missing');
    res.json({ paymentUrl: checkoutUrl });

  } catch (err) {
    if (err.providerEvidence) {
      appendEvidence({
        provider: err.providerEvidence.provider,
        provider_scope: err.providerEvidence.provider_scope,
        http_status: err.providerEvidence.http_status,
        explicit_success: false,
        provider_request_id: err.providerEvidence.provider_request_id,
        provider_request_id_source: err.providerEvidence.provider_request_id_source,
        provider_request_id_exposed: err.providerEvidence.provider_request_id_exposed,
        idempotency_key: err.providerEvidence.idempotency_key,
        production_binding_verified: false,
        error_type: err.name || 'Error'
      });
    }
    res.status(500).json({ error: 'Betaling mislukt' });
  }
});

module.exports = router;
