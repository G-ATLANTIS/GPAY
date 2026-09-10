#!/usr/bin/env node
'use strict';

// Operator CLI for live Mollie payment creation.
//
// RETIRED direct path: this used to drive GBankLiveCore.execute() which had its
// own authorization/idempotency/verdict. It now builds a canonical spine
// request and the ONLY way it reaches Mollie is:
//
//   executeVerified(request, context)  ->  MollieSpineConnector  ->  MollieLiveAdapter
//
// There is no legacy fallback.
//
//   preflight               read-only Mollie LIVE capability probe
//   prepare  <intent.json> <bundle.json>     build the canonical spine request
//   authorize <bundle.json> <approval.json>  mint the bound HMAC authorization
//   execute  <bundle.json> <approval.json> --execute-live   run through the spine
//   reconcile <idempotency_key> [payment_id]  recover a quarantined execution

const fs = require('node:fs');
const path = require('node:path');

const { normalizeIntent, newIdempotencyKey, sha256 } = require('../backend/g-bank-live-v1/canonical');
const { MollieLiveAdapter } = require('../backend/g-bank-live-v1/providers/mollie-live');
const { executeVerified, reconcile } = require('../backend/g-verified-execution-spine/spine');
const { createAuthorization } = require('../backend/g-verified-execution-spine/authorization');
const { SequenceStore } = require('../backend/g-verified-execution-spine/sequence-store');
const {
  MOLLIE_CAPABILITY,
  MOLLIE_OPERATION,
  buildMollieRegistry,
  buildMolliePolicy,
  buildMollieRequest,
  mollieBindingSha256,
} = require('../backend/g-verified-execution-spine/gbank-mollie-routing');

const STATE_DIR = path.resolve(process.env.G_BANK_LIVE_STATE_DIR || '.secrets/g-bank-live-state');
const ACTOR = process.env.G_BANK_ACTOR || 'operator:cli';

function die(message, code = 2) {
  console.error(message);
  process.exit(code);
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

function maxAmountMinor() {
  const eur = Number(process.env.G_BANK_MAX_PAYMENT_EUR || '0');
  const minor = Math.round(eur * 100);
  if (!Number.isSafeInteger(minor) || minor <= 0) {
    die('G_BANK_MAX_PAYMENT_EUR must be set to a positive amount (fail-closed payment cap).');
  }
  return minor;
}

function registry(adapter) {
  return buildMollieRegistry({ adapter: adapter || new MollieLiveAdapter(), env: process.env });
}

function streamName() {
  return `${ACTOR}::${MOLLIE_CAPABILITY}`;
}

async function main() {
  const [command, ...args] = process.argv.slice(2);

  if (command === 'preflight') {
    const connector = registry().resolve(MOLLIE_CAPABILITY);
    const result = await connector.discover({ allowExternalEffects: true, env: process.env });
    console.log(JSON.stringify(result, null, 2));
    console.log('PAYMENT_ENDPOINT_CALLED = FALSE');
    console.log('VALUE_MOVED = FALSE');
    if (result.ok !== true) process.exit(1);
    return;
  }

  if (command === 'prepare') {
    const [intentFile, out] = args;
    if (!intentFile || !out) die('usage: prepare <intent.json> <bundle.json>');
    const intent = normalizeIntent(readJson(intentFile));
    const seq = new SequenceStore(path.join(STATE_DIR, 'sequence'));
    const expectedSequence = seq.current(streamName()) + 1;
    const idempotencyKey = newIdempotencyKey();
    const request = buildMollieRequest({
      actor: ACTOR,
      requestId: `gbank-cli-${idempotencyKey}`,
      intent,
      idempotencyKey,
      expectedSequence,
    });
    const bundle = {
      schema: 'g-bank-live-execution-bundle/v2',
      capability: MOLLIE_CAPABILITY,
      operation: MOLLIE_OPERATION,
      request,
      request_canonical_sha256: mollieBindingSha256(request),
      intent_sha256: intent.intent_sha256,
      prepared_at: new Date().toISOString(),
    };
    console.log('BUNDLE =', writeSecretJson(out, bundle));
    console.log('EXPECTED_SEQUENCE =', expectedSequence);
    console.log('PAYMENT_CREATED = FALSE');
    console.log('VALUE_MOVED = FALSE');
    return;
  }

  if (command === 'authorize') {
    const [bundleFile, out] = args;
    if (!bundleFile || !out) die('usage: authorize <bundle.json> <approval.json>');
    const bundle = readJson(bundleFile);
    const request = bundle.request;
    const binding = mollieBindingSha256(request);
    if (binding !== bundle.request_canonical_sha256) die('bundle_request_canonical_sha256_mismatch');
    const token = createAuthorization(
      {
        requestCanonicalSha256: binding,
        idempotencyKey: request.idempotency_key,
        actor: request.actor,
        capability: request.requested_capability,
        operation: request.operation,
        ttl_seconds: Number(process.env.G_BANK_APPROVAL_TTL_SECONDS || '300'),
      },
      process.env,
    );
    const approval = {
      schema: 'g-bank-live-approval-envelope/v2',
      capability: request.requested_capability,
      operation: request.operation,
      request_canonical_sha256: binding,
      idempotency_key_sha256: sha256(request.idempotency_key),
      token,
      created_at: new Date().toISOString(),
    };
    console.log('APPROVAL =', writeSecretJson(out, approval));
    console.log('PAYMENT_CREATED = FALSE');
    console.log('VALUE_MOVED = FALSE');
    return;
  }

  if (command === 'execute') {
    const [bundleFile, approvalFile] = args;
    if (!bundleFile || !approvalFile || !args.includes('--execute-live')) {
      die('usage: execute <bundle.json> <approval.json> --execute-live');
    }
    if (process.env.G_BANK_OPERATOR_CONFIRMATION !== 'I_AUTHORIZE_THIS_REAL_PAYMENT') {
      die('G_BANK_OPERATOR_CONFIRMATION=I_AUTHORIZE_THIS_REAL_PAYMENT required');
    }
    const bundle = readJson(bundleFile);
    const approval = readJson(approvalFile);
    const request = { ...bundle.request };
    if (approval.request_canonical_sha256 !== bundle.request_canonical_sha256) {
      die('approval_bundle_request_mismatch');
    }
    request.authorization_token = approval.token;

    const result = await executeVerified(request, {
      env: process.env,
      stateDir: STATE_DIR,
      registry: registry(),
      policy: buildMolliePolicy({ actor: request.actor, maxAmountMinor: maxAmountMinor() }),
      allowExternalEffects: true,
    });
    console.log(JSON.stringify(result, null, 2));
    if (result.state !== 'VERIFIED_SUCCESS') {
      console.error('G_BANK_LIVE_V1_NOT_VERIFIED =', result.state, result.detail || '');
      process.exit(2);
    }
    return;
  }

  if (command === 'reconcile') {
    const [idempotencyKey, paymentId] = args;
    if (!idempotencyKey) die('usage: reconcile <idempotency_key> [mollie-payment-id]');
    const result = await reconcile(
      { idempotency_key: idempotencyKey, provider_request_id: paymentId || null },
      { env: process.env, stateDir: STATE_DIR, registry: registry(), capability: MOLLIE_CAPABILITY },
    );
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  die('commands: preflight | prepare | authorize | execute | reconcile');
}

main().catch((err) => {
  console.error('G_BANK_LIVE_V1_BLOCKED =', err.message || String(err));
  if (err.provider_http_status) console.error('PROVIDER_HTTP_STATUS =', err.provider_http_status);
  process.exit(2);
});
