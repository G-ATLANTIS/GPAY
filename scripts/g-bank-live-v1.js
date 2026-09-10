#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { normalizeIntent, newIdempotencyKey } = require('../backend/g-bank-live-v1/canonical');
const { createApproval } = require('../backend/g-bank-live-v1/approval');
const { GBankLiveCore } = require('../backend/g-bank-live-v1/live-core');
const { MollieLiveAdapter } = require('../backend/g-bank-live-v1/providers/mollie-live');

function die(message) {
  console.error(message);
  process.exit(2);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(path.resolve(file), 'utf8'));
}

function writeSecretJson(file, value) {
  const resolved = path.resolve(file);
  fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  fs.writeFileSync(resolved, JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  return resolved;
}

function core() {
  return new GBankLiveCore({
    adapters: { 'mollie-live': new MollieLiveAdapter() },
  });
}

async function main() {
  const [command, ...args] = process.argv.slice(2);

  if (command === 'preflight') {
    const provider = args[0] || 'mollie-live';
    const result = await core().preflight(provider);
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (command === 'prepare') {
    const intentFile = args[0];
    const out = args[1];
    if (!intentFile || !out) die('usage: prepare <intent.json> <bundle.json>');
    const intent = normalizeIntent(readJson(intentFile));
    const bundle = {
      schema: 'g-bank-live-execution-bundle/v1',
      provider: 'mollie-live',
      idempotency_key: newIdempotencyKey(),
      intent,
      prepared_at: new Date().toISOString(),
    };
    console.log('BUNDLE =', writeSecretJson(out, bundle));
    console.log('PAYMENT_CREATED = FALSE');
    console.log('VALUE_MOVED = FALSE');
    return;
  }

  if (command === 'authorize') {
    const bundleFile = args[0];
    const out = args[1];
    if (!bundleFile || !out) die('usage: authorize <bundle.json> <approval.json>');
    const bundle = readJson(bundleFile);
    const intent = normalizeIntent(bundle.intent);
    const token = createApproval({
      intent,
      provider: bundle.provider,
      idempotencyKey: bundle.idempotency_key,
    });
    const approval = {
      schema: 'g-bank-live-approval-envelope/v1',
      provider: bundle.provider,
      intent_sha256: intent.intent_sha256,
      idempotency_key: bundle.idempotency_key,
      token,
      created_at: new Date().toISOString(),
    };
    console.log('APPROVAL =', writeSecretJson(out, approval));
    console.log('PAYMENT_CREATED = FALSE');
    console.log('VALUE_MOVED = FALSE');
    return;
  }

  if (command === 'execute') {
    const bundleFile = args[0];
    const approvalFile = args[1];
    if (!bundleFile || !approvalFile || !args.includes('--execute-live')) {
      die('usage: execute <bundle.json> <approval.json> --execute-live');
    }
    if (process.env.G_BANK_OPERATOR_CONFIRMATION !== 'I_AUTHORIZE_THIS_REAL_PAYMENT') {
      die('G_BANK_OPERATOR_CONFIRMATION=I_AUTHORIZE_THIS_REAL_PAYMENT required');
    }
    const bundle = readJson(bundleFile);
    const approval = readJson(approvalFile);
    if (approval.idempotency_key !== bundle.idempotency_key) die('approval_bundle_idempotency_mismatch');
    const result = await core().execute({
      rawIntent: bundle.intent,
      provider: bundle.provider,
      approvalToken: approval.token,
      idempotencyKey: bundle.idempotency_key,
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (command === 'reconcile') {
    const paymentId = args[0];
    if (!paymentId) die('usage: reconcile <mollie-payment-id>');
    const adapter = new MollieLiveAdapter();
    const result = await adapter.getPayment(paymentId);
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  die('commands: preflight | prepare | authorize | execute | reconcile');
}

main().catch(err => {
  console.error('G_BANK_LIVE_V1_BLOCKED =', err.message || String(err));
  if (err.provider_http_status) console.error('PROVIDER_HTTP_STATUS =', err.provider_http_status);
  if (err.provider_detail) console.error('PROVIDER_DETAIL =', err.provider_detail);
  process.exit(2);
});
