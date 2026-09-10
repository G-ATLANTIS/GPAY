'use strict';

// G-BANK-CANONICAL-LIVE-ROUTING-P0
//
// This route previously called `mollieClient.payments.create(...)` directly —
// a live provider mutation with no authorization, idempotency, sequencing,
// readback or audit. That bypass is removed. The only path to Mollie now is:
//
//   executeVerified(request, ctx) -> MollieSpineConnector -> MollieLiveAdapter
//
// Fail-closed by default: without an operator secret AND the live-execution
// environment flags, this route denies.

const express = require('express');
const crypto = require('node:crypto');

const { normalizeIntent, newIdempotencyKey } = require('../g-bank-live-v1/canonical');
const { executeVerified } = require('../g-verified-execution-spine/spine');
const { createAuthorization } = require('../g-verified-execution-spine/authorization');
const { SequenceStore } = require('../g-verified-execution-spine/sequence-store');
const {
  MOLLIE_CAPABILITY,
  buildMollieRegistry,
  buildMolliePolicy,
  buildMollieRequest,
  mollieBindingSha256,
} = require('../g-verified-execution-spine/gbank-mollie-routing');
const checkFraud = require('../utils/g-fraud');

const router = express.Router();

const STATE_DIR = process.env.G_BANK_LIVE_STATE_DIR || '.secrets/g-bank-live-state';
const ACTOR = 'route:mollie-create-payment';

function operatorAuthorized(req) {
  const secret = String(process.env.G_BANK_OPERATOR_SECRET || '');
  if (secret.length < 32) return false;
  const supplied = Buffer.from(String(req.get('X-G-Bank-Operator-Authorization') || ''), 'utf8');
  const expected = Buffer.from(secret, 'utf8');
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function maxAmountMinor() {
  const minor = Math.round(Number(process.env.G_BANK_MAX_PAYMENT_EUR || '0') * 100);
  return Number.isSafeInteger(minor) && minor > 0 ? minor : 0;
}

router.post('/create-payment', async (req, res) => {
  try {
    if (!operatorAuthorized(req)) {
      return res.status(403).json({ error: 'operator_authorization_required', payment_created: false, value_moved: false });
    }
    const cap = maxAmountMinor();
    if (cap === 0) {
      return res.status(503).json({ error: 'G_BANK_MAX_PAYMENT_EUR_not_configured', payment_created: false });
    }

    const { amount, orderId, email, method } = req.body || {};
    if (checkFraud(req.ip, amount, req.headers['user-agent'])) {
      return res.status(403).json({ error: 'fraud_suspected', payment_created: false });
    }

    const amountMinor = Math.round(Number(amount) * 100);
    const intent = normalizeIntent({
      intent_id: `order-${String(orderId || 'na')}-${Date.now()}`,
      amount_minor: amountMinor,
      currency: 'EUR',
      description: `Order ${orderId}`,
      destination_binding: `mollie-order:${String(orderId || 'na')}`,
      redirect_url: process.env.G_BANK_MOLLIE_REDIRECT_URL || null,
      webhook_url: process.env.G_BANK_MOLLIE_WEBHOOK_URL || null,
      metadata: { orderId: String(orderId || ''), email: String(email || ''), method: String(method || '') },
    });

    const seq = new SequenceStore(require('node:path').join(STATE_DIR, 'sequence'));
    const stream = `${ACTOR}::${MOLLIE_CAPABILITY}`;
    const idempotencyKey = req.get('Idempotency-Key') || newIdempotencyKey();
    const request = buildMollieRequest({
      actor: ACTOR,
      requestId: `route-${idempotencyKey}`,
      intent,
      idempotencyKey,
      expectedSequence: seq.current(stream) + 1,
    });
    // Operator-authenticated: the server mints the spine authorization bound to
    // this exact canonical request.
    request.authorization_token = createAuthorization(
      {
        requestCanonicalSha256: mollieBindingSha256(request),
        idempotencyKey: request.idempotency_key,
        actor: request.actor,
        capability: request.requested_capability,
        operation: request.operation,
        ttl_seconds: 120,
      },
      process.env,
    );

    const result = await executeVerified(request, {
      env: process.env,
      stateDir: STATE_DIR,
      registry: buildMollieRegistry({ env: process.env }),
      policy: buildMolliePolicy({ actor: ACTOR, maxAmountMinor: cap }),
      allowExternalEffects: true,
    });

    if (result.state !== 'VERIFIED_SUCCESS') {
      return res.status(result.state === 'DENIED_AUTHORIZATION' || result.state === 'DENIED_POLICY' ? 403 : 502).json({
        error: 'not_verified',
        state: result.state,
        detail: result.detail || null,
        payment_created: false,
        value_moved: false,
      });
    }
    return res.json({
      state: result.state,
      provider_request_id: result.provider_request_id,
      checkout_url: result.execution_result && result.execution_result.receipt
        ? result.execution_result.receipt.checkout_url || null
        : null,
      assurance_level_achieved: result.assurance_level_achieved,
      audit_entry_hash: result.audit_entry_hash,
    });
  } catch (err) {
    return res.status(500).json({ error: 'mollie_route_failed', detail: err.message, payment_created: false });
  }
});

module.exports = router;
