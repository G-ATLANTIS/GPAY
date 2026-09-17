#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { evaluateCurrent, eurToMinor } = require('../../scripts/atlas-payment-v2-readiness');

assert.equal(eurToMinor('294900'), 29490000);
assert.throws(() => eurToMinor('0'), /amount_eur_invalid/);

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'atlas-pay-v2-'));
fs.mkdirSync(path.join(root, '.secrets/production'), { recursive: true });
fs.mkdirSync(path.join(root, '.secrets/evidence'), { recursive: true });
fs.writeFileSync(path.join(root, '.env'), 'G_BANK_MAX_PAYMENT_EUR=100\n');
fs.writeFileSync(
  path.join(root, '.secrets/production/truelayer.env'),
  [
    'TRUELAYER_ENV=live',
    'G_BANK_ENABLE_LIVE=false',
    'TRUELAYER_CLIENT_ID=id',
    'TRUELAYER_CLIENT_SECRET=secretsecret',
    'TRUELAYER_SIGNING_KID=kid',
    'TRUELAYER_PRIVATE_KEY_B64=key'
  ].join('\n') + '\n'
);
fs.writeFileSync(
  path.join(root, '.secrets/evidence/g-payment-live-oauth-proof.json'),
  JSON.stringify({
    oauth_scope: 'payments',
    provider_authentication_verified: false,
    payments_scope_accepted: false,
    oauth_error: 'invalid_scope'
  })
);

const report = evaluateCurrent({ baseDir: root, amountEur: '294900' });
assert.equal(report.production_environment, 'live');
assert.equal(report.provider_credentials_present, true);
assert.equal(report.provider_entitlement_verified, false);
assert.equal(report.configured_max_payment_eur, 100);
assert.equal(report.scheme_selection, 'USER_SELECTED_SEPA');
assert.equal(report.sca_required, true);
assert.equal(report.state, 'BLOCKED');
assert(report.blockers.includes('BANK_LIMIT_VERIFICATION_REQUIRED'));
assert(report.blockers.includes('LOCAL_POLICY_LIMIT_INSUFFICIENT'));
assert.equal(report.bank_limit_verified, false);
assert(report.blockers.includes('PROVIDER_ENTITLEMENT_REQUIRED'));
assert(report.blockers.includes('SCA_PATH_NOT_READY'));
assert.equal(report.payment_endpoint_called, false);
assert.equal(report.value_moved, false);

fs.writeFileSync(path.join(root, '.env'), 'G_BANK_MAX_PAYMENT_EUR=300000\n');
fs.writeFileSync(
  path.join(root, '.secrets/evidence/atlas-bank-limit-proof.json'),
  JSON.stringify({
    schema: 'atlas-bank-limit-proof-v1',
    verified: true,
    source: 'BANK_PROVIDER_READBACK',
    currency: 'EUR',
    max_amount_in_minor: 30_000_000,
    evidence_sha256: 'a'.repeat(64),
    observed_at: new Date().toISOString()
  })
);
const withBankProof = evaluateCurrent({ baseDir: root, amountEur: '294900' });
assert.equal(withBankProof.bank_limit_verified, true);
assert.equal(withBankProof.bank_limit_in_minor, 30_000_000);
assert(!withBankProof.blockers.includes('BANK_LIMIT_VERIFICATION_REQUIRED'));
assert(!withBankProof.blockers.includes('BANK_LIMIT_INSUFFICIENT'));
assert(!withBankProof.blockers.includes('LOCAL_POLICY_LIMIT_INSUFFICIENT'));

fs.rmSync(root, { recursive: true, force: true });
console.log('atlas-payment-v2-readiness: PASS');
