'use strict';

// G-BANK-CANONICAL-LIVE-ROUTING-P0
//
// This handler previously fetched a Mollie payment straight from
// `@mollie/api-client` on an unauthenticated webhook body and then granted
// token rewards, generated an invoice and sent email — side effects driven by
// unverified external input, with no spine involvement. It is also not mounted
// by any server (`backend/index.js` / `backend/banking-server.js` do not use
// it), i.e. dead code.
//
// It is neutralised to a fail-closed stub. A real Mollie webhook must:
//   1. take ONLY the payment id from the notification,
//   2. perform an authenticated provider readback,
//   3. drive any state change through executeVerified() + a spine connector.

const express = require('express');
const router = express.Router();

router.post('/mollie/webhook', (req, res) => {
  res.status(501).json({
    error: 'mollie_webhook_handler_retired',
    detail:
      'Reward/invoice/email side effects from an unverified webhook body are disabled. ' +
      'Reconcile via an authenticated readback through G_VERIFIED_EXECUTION_SPINE.',
    payment_created: false,
    value_moved: false,
  });
});

module.exports = router;
