#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const dotenv = require('dotenv');
const { evaluatePreExecution } = require('./atlas-payment-v2-policy');

function eurToMinor(value) {
  const text = String(value ?? '').trim();
  if (!/^\d+(?:\.\d{1,2})?$/.test(text)) throw new Error('amount_eur_invalid');
  const minor = Math.round(Number(text) * 100);
  if (!Number.isSafeInteger(minor) || minor <= 0) throw new Error('amount_eur_invalid');
  return minor;
}

function loadEnvFile(file) {
  if (!fs.existsSync(file)) return {};
  return dotenv.parse(fs.readFileSync(file, 'utf8'));
}

function isTrue(value) {
  return String(value || '').trim().toLowerCase() === 'true';
}

function isSet(value) {
  return typeof value === 'string' && value.trim().length > 0;
}
function latestOauthProof(baseDir) {
  const candidates = [
    '.secrets/evidence/g-payment-live-oauth-proof.json',
    'G_PAYMENT_LIVE_OAUTH_PROOF_CAPTURE.json'
  ].map(value => path.join(baseDir, value));

  for (const file of candidates) {
    if (!fs.existsSync(file)) continue;
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      return { file, proof: parsed };
    } catch {
      return { file, proof: null };
    }
  }
  return { file: null, proof: null };
}

function evaluateCurrent({ baseDir, amountEur }) {
  const active = loadEnvFile(path.join(baseDir, '.env'));
  const prodPath = path.join(baseDir, '.secrets/production/truelayer.env');
  const prod = loadEnvFile(prodPath);
  const { file: proofFile, proof } = latestOauthProof(baseDir);
  const amount = eurToMinor(amountEur);

  const signingReady = [
    prod.TRUELAYER_CLIENT_ID,
    prod.TRUELAYER_CLIENT_SECRET,
    prod.TRUELAYER_SIGNING_KID,
    prod.TRUELAYER_PRIVATE_KEY_B64 || prod.TRUELAYER_PRIVATE_KEY_PEM
  ].every(isSet);
  const providerEntitlementVerified = Boolean(
    proof &&
    proof.provider_authentication_verified === true &&
    proof.payments_scope_accepted === true &&
    proof.oauth_scope === 'payments'
  );

  const effectiveMaxEur = Number(
    prod.G_BANK_MAX_PAYMENT_EUR || active.G_BANK_MAX_PAYMENT_EUR || 0
  );
  const bankLimitMinor = Number.isFinite(effectiveMaxEur)
    ? Math.round(effectiveMaxEur * 100)
    : 0;

  const policy = evaluatePreExecution({
    amount_in_minor: amount,
    currency: 'EUR',
    owner_approved: false,
    provider_entitlement_verified: providerEntitlementVerified,
    beneficiary_verified: false,
    bank_limit_verified: bankLimitMinor > 0,
    bank_limit_minor: bankLimitMinor,
    signing_ready: signingReady,
    idempotency_bound: false,
    sca_capable: false,
    live_gate_enabled: isTrue(prod.G_BANK_ENABLE_LIVE),
    provider_id_verified: false,
    provider_supports_sepa_credit: false
  });

  return {
    schema: 'atlas-payment-v2-readiness-v1',
    amount_eur: Number(amountEur),
    amount_in_minor: amount,
    production_config_present: fs.existsSync(prodPath),
    production_environment: String(prod.TRUELAYER_ENV || '').toLowerCase() || 'unset',
    provider_credentials_present: signingReady,
    provider_oauth_proof_file_present: Boolean(proofFile),
    provider_entitlement_verified: providerEntitlementVerified,
    provider_oauth_error: proof?.oauth_error || null,
    configured_max_payment_eur: effectiveMaxEur || null,
    live_gate_enabled: isTrue(prod.G_BANK_ENABLE_LIVE),
    scheme_selection: policy.scheme_selection,
    sca_required: policy.sca_required,
    state: policy.state,
    blockers: policy.blockers,
    payment_endpoint_called: false,
    payment_created: false,
    value_moved: false,
    secret_values_emitted: false
  };
}

function main(argv = process.argv.slice(2)) {
  const amountIndex = argv.indexOf('--amount-eur');
  if (amountIndex < 0 || !argv[amountIndex + 1]) {
    throw new Error('usage: --amount-eur <EUR>');
  }
  const report = evaluateCurrent({
    baseDir: process.cwd(),
    amountEur: argv[amountIndex + 1]
  });
  console.log(JSON.stringify(report, null, 2));
  return report.state === 'READY_TO_CREATE_PAYMENT' ? 0 : 2;
}

if (require.main === module) {
  try { process.exitCode = main(); }
  catch (error) {
    console.error(String(error.message || error));
    process.exitCode = 2;
  }
}

module.exports = { eurToMinor, loadEnvFile, evaluateCurrent };
