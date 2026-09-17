#!/usr/bin/env node
'use strict';

const BANKS = Object.freeze([
  { id: 'bunq', key: 'BUNQ_API_KEY', env: 'BUNQ_ENV' },
  { id: 'yapily', key: 'YAPILY_APPLICATION_KEY', secret: 'YAPILY_APPLICATION_SECRET', env: 'YAPILY_ENV' },
  { id: 'mollie', key: 'MOLLIE_API_KEY' },
  { id: 'ing', key: 'ING_CLIENT_ID' },
  { id: 'rabobank', key: 'RABOBANK_CLIENT_ID' },
  { id: 'abn-amro', key: 'ABN_CLIENT_ID' }
]);

function present(env, name) {
  return typeof env[name] === 'string' && env[name].trim().length > 0;
}

function discover(env = process.env) {
  const candidates = BANKS.map(bank => {
    const primary = present(env, bank.key);
    const secondary = bank.secret ? present(env, bank.secret) : true;
    return {
      bank_id: bank.id,
      credentials_present: primary && secondary,
      environment: bank.env ? String(env[bank.env] || 'unset').toLowerCase() : 'unknown',
      production_verified: false,
      read_only_probe_performed: false,
      value_moved: false
    };
  });  const eligible = candidates.filter(x => x.credentials_present);
  return {
    schema: 'atlas-open-banking-bank-discovery-v1',
    candidates,
    configured_candidate_count: eligible.length,
    selected_bank_id: null,
    state: eligible.length ? 'CREDENTIALS_PRESENT_PROBE_REQUIRED' : 'BLOCKED_NO_BANK_CREDENTIALS',
    payment_endpoint_call_permitted: false,
    value_moved: false
  };
}

if (require.main === module) {
  const result = discover();
  console.log(JSON.stringify(result, null, 2));
  if (result.state !== 'CREDENTIALS_PRESENT_PROBE_REQUIRED') process.exitCode = 2;
}

module.exports = { BANKS, discover };
