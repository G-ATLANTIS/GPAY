#!/usr/bin/env node
'use strict';

const path = require('node:path');
const {
  evaluateCurrent,
  loadEnvFile
} = require('./atlas-payment-v2-readiness');
const {
  evaluateNetworkReadiness
} = require('./atlas-payment-v2-network-readiness');

function combineReports(local, network) {
  const localReady = local?.state === 'READY_TO_CREATE_PAYMENT';
  const networkReady = network?.state === 'READY';
  const blockers = Array.from(new Set([
    ...(local?.blockers || []),
    ...(network?.blockers || [])
  ])).sort();

  return {
    schema: 'atlas-payment-production-audit-v2',
    amount_eur: local?.amount_eur ?? null,
    amount_in_minor: local?.amount_in_minor ?? null,
    scheme_selection: local?.scheme_selection ?? null,
    local_pre_execution_ready: localReady,
    public_callback_ready: networkReady,
    state: localReady && networkReady ? 'READY_FOR_PAYMENT_CREATE' : 'BLOCKED',
    blockers,
    provider_oauth_error: local?.provider_oauth_error ?? null,
    configured_max_payment_eur: local?.configured_max_payment_eur ?? null,
    webhook_http_status: network?.webhook_http_status ?? null,
    return_http_status: network?.return_http_status ?? null,
    webhook_environment: network?.webhook_environment ?? null,
    payment_endpoint_called: false,
    payment_created: false,
    value_moved: false
  };
}

function callbackBaseFromProduction(baseDir) {
  const prod = loadEnvFile(
    path.join(baseDir, '.secrets/production/truelayer.env')
  );
  const value = String(prod.TRUELAYER_RETURN_URI || '').trim();
  if (!value) return 'https://bank.gijs.live';
  try {
    return new URL(value).origin;
  } catch {
    return 'https://bank.gijs.live';
  }
}

async function evaluateAudit({ baseDir, amountEur, fetch_impl = globalThis.fetch }) {
  const local = evaluateCurrent({ baseDir, amountEur });
  const baseUrl = callbackBaseFromProduction(baseDir);
  const network = await evaluateNetworkReadiness({ base_url: baseUrl, fetch_impl });
  return combineReports(local, network);
}
async function main(argv = process.argv.slice(2)) {
  const amountIndex = argv.indexOf('--amount-eur');
  if (amountIndex < 0 || !argv[amountIndex + 1]) {
    throw new Error('usage: --amount-eur <EUR>');
  }
  const report = await evaluateAudit({
    baseDir: process.cwd(),
    amountEur: argv[amountIndex + 1]
  });
  console.log(JSON.stringify(report, null, 2));
  return report.state === 'READY_FOR_PAYMENT_CREATE' ? 0 : 2;
}

if (require.main === module) {
  main().then(code => { process.exitCode = code; }).catch(error => {
    console.error(String(error.message || error));
    process.exitCode = 2;
  });
}

module.exports = {
  combineReports,
  callbackBaseFromProduction,
  evaluateAudit,
  main
};
