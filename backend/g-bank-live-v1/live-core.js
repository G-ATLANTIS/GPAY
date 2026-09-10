'use strict';

// RETIRED — G-BANK-CANONICAL-LIVE-ROUTING-P0
//
// GBankLiveCore used to be an independent live payment orchestrator: it
// implemented its own authorization check, its own idempotency ownership, the
// provider POST, readback and a "verified" success verdict. That made it a
// second execution authority that could diverge from — and bypass — the
// canonical G_VERIFIED_EXECUTION_SPINE.
//
// It is now retired. All live Mollie execution goes through:
//
//   executeVerified(request, context)  +  MollieSpineConnector
//
// (see scripts/g-bank-live-v1.js and backend/g-verified-execution-spine/).
//
// `requireLiveExecution` is kept: it is a pure environment guard with no
// execution behaviour, and the spine's Mollie connector reuses it.

function requireLiveExecution(env = process.env) {
  if (env.G_BANK_ENABLE_LIVE !== 'true') throw new Error('g_bank_live_execution_disabled');
  if (env.G_BANK_EXTERNAL_ACTIONS_ENABLED !== 'true') throw new Error('g_bank_external_actions_disabled');
  if (env.G_BANK_SIMULATED_LIVE_SUCCESS === 'true') throw new Error('simulated_live_success_forbidden');
  return true;
}

const RETIREMENT_MESSAGE =
  'GBankLiveCore is retired. Route live Mollie execution through ' +
  'executeVerified() + MollieSpineConnector (scripts/g-bank-live-v1.js / ' +
  'backend/g-verified-execution-spine). Direct provider execution is DENY.';

class GBankLiveCore {
  constructor() {
    throw new Error(RETIREMENT_MESSAGE);
  }

  static get retired() {
    return true;
  }
}

module.exports = { GBankLiveCore, requireLiveExecution, RETIREMENT_MESSAGE };
