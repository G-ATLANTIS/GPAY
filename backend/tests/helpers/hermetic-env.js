'use strict';

// Reusable test isolation for security-relevant environment state.
//
// Some modules (via dotenv) load a developer's .env into process.env before a
// test file's own snapshot runs. A test that asserts fail-closed / default-deny
// behaviour must NOT inherit that ambient state (e.g. an ambient
// G_BANK_EXTERNAL_ACTIONS_ENABLED=true, or a real TRUELAYER_PRIVATE_KEY_B64).
//
//   const { isolateBankingEnv } = require('./helpers/hermetic-env');
//   isolateBankingEnv();            // clears the vars, restores them on exit
//
// The test then sets exactly the values its scenario needs. CI, which has none
// of these set, is unaffected.

const BANKING_ENV_KEYS = [
  // execution gates
  'G_BANK_ENABLE_LIVE',
  'G_BANK_EXTERNAL_ACTIONS_ENABLED',
  'G_BANK_SIMULATED_LIVE_SUCCESS',
  'G_BANK_OPERATOR_CONFIRMATION',
  // secrets / auth
  'G_BANK_APPROVAL_SECRET',
  'G_BANK_OPERATOR_SECRET',
  'G_SPINE_AUTHORIZATION_SECRET',
  'G_BANK_PROVIDER_PROBE_SECRET',
  'G_BANK_ENABLE_PROVIDER_PROBE',
  // limits / allowlists
  'G_BANK_MAX_PAYMENT_EUR',
  'G_BANK_ALLOWED_BENEFICIARY_IBANS',
  // provider credentials / environment
  'TRUELAYER_ENV',
  'TRUELAYER_CLIENT_ID',
  'TRUELAYER_CLIENT_SECRET',
  'TRUELAYER_SIGNING_KID',
  'TRUELAYER_PRIVATE_KEY_B64',
  'TRUELAYER_PRIVATE_KEY_PEM',
  'TRUELAYER_RETURN_URI',
  'MOLLIE_API_KEY',
  // durable-location gates
  'G_BANK_WEBHOOK_RECEIPT_DIR',
  'G_BANK_PAYMENT_INTENT_DIR',
  'G_CHAT_PAYMENT_INTENT_DIR',
  'G_BANK_LIVE_STATE_DIR',
];

function isolateEnv(keys) {
  const snapshot = {};
  for (const k of keys) {
    snapshot[k] = process.env[k];
    delete process.env[k];
  }
  let restored = false;
  const restore = () => {
    if (restored) return;
    restored = true;
    for (const [k, v] of Object.entries(snapshot)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };
  process.on('exit', restore);
  return { snapshot, restore, keys: [...keys] };
}

function isolateBankingEnv(extraKeys = []) {
  return isolateEnv([...new Set([...BANKING_ENV_KEYS, ...extraKeys])]);
}

module.exports = { isolateBankingEnv, isolateEnv, BANKING_ENV_KEYS };
