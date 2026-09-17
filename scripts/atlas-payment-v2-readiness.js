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

function latestBankLimitProof(baseDir) {
  const file = path.join(baseDir, '.secrets/evidence/atlas-bank-limit-proof.json');
  if (!fs.existsSync(file)) return { file: null, proof: null, verified: false };
  try {
    const proof = JSON.parse(fs.readFileSync(file, 'utf8'));
    const observedAt = Date.parse(proof.observed_at);
    const ageMs = Date.now() - observedAt;
    const verified =
      proof.schema === 'atlas-bank-limit-proof-v1' &&
      proof.verified === true &&
      proof.source === 'BANK_PROVIDER_READBACK' &&
      String(proof.currency || '').toUpperCase() === 'EUR' &&
      Number.isSafeInteger(proof.max_amount_in_minor) &&
      proof.max_amount_in_minor > 0 &&
      /^[0-9a-f]{64}$/i.test(String(proof.evidence_sha256 || '')) &&
      Number.isFinite(observedAt) && ageMs >= -5000 && ageMs <= 24 * 60 * 60 * 1000;
    return { file, proof, verified };
  } catch {
    return { file, proof: null, verified: false };
  }
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
  const localPolicyLimitMinor = Number.isFinite(effectiveMaxEur)
    ? Math.round(effectiveMaxEur * 100)
    : 0;
  const bankLimit = latestBankLimitProof(baseDir);
  const bankLimitMinor = bankLimit.verified
    ? Number(bankLimit.proof.max_amount_in_minor)
    : 0;

  const policy = evaluatePreExecution({
    amount_in_minor: amount,
    currency: 'EUR',
    owner_approved: false,
    provider_entitlement_verified: providerEntitlementVerified,
    beneficiary_verified: false,
    bank_limit_verified: bankLimit.verified,
    bank_limit_minor: bankLimitMinor,
    signing_ready: signingReady,
    idempotency_bound: false,
    sca_capable: false,
    live_gate_enabled: isTrue(prod.G_BANK_ENABLE_LIVE),
    scheme_selection_capable: true
  });

  const blockers = [...policy.blockers];
  if (localPolicyLimitMinor < amount) blockers.push('LOCAL_POLICY_LIMIT_INSUFFICIENT');
  const uniqueBlockers = Array.from(new Set(blockers)).sort();

  return {
    schema: 'atlas-payment-v2-readiness-v2',
    amount_eur: Number(amountEur),
    amount_in_minor: amount,
    production_config_present: fs.existsSync(prodPath),
    production_environment: String(prod.TRUELAYER_ENV || '').toLowerCase() || 'unset',
    provider_credentials_present: signingReady,
    provider_oauth_proof_file_present: Boolean(proofFile),
    provider_entitlement_verified: providerEntitlementVerified,
    provider_oauth_error: proof?.oauth_error || null,
    configured_max_payment_eur: effectiveMaxEur || null,
    local_policy_limit_in_minor: localPolicyLimitMinor,
    bank_limit_evidence_present: Boolean(bankLimit.file),
    bank_limit_verified: bankLimit.verified,
    bank_limit_in_minor: bankLimitMinor || null,
    live_gate_enabled: isTrue(prod.G_BANK_ENABLE_LIVE),
    scheme_selection: policy.scheme_selection,
    sca_required: policy.sca_required,
    state: uniqueBlockers.length === 0 ? 'READY_TO_CREATE_PAYMENT' : 'BLOCKED',
    blockers: uniqueBlockers,
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

module.exports = { eurToMinor, loadEnvFile, latestBankLimitProof, evaluateCurrent };
