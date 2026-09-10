#!/usr/bin/env node
'use strict';

// TRUELAYER-SANDBOX-E2E-VERIFICATION-P0
//
// Opt-in external verification of the real TrueLayer *sandbox* payment path
// through G_VERIFIED_EXECUTION_SPINE. It creates AT MOST ONE sandbox payment,
// reads it back independently, verifies idempotency and reconciliation, and
// writes a redacted machine-readable evidence receipt.
//
//   TRUELAYER_ENV=sandbox G_BANK_ENABLE_LIVE=false \
//   G_BANK_ENABLE_SANDBOX_EXTERNAL=true \
//   G_SPINE_AUTHORIZATION_SECRET=<32+ bytes> \
//   G_BANK_SANDBOX_SMOKE_BENEFICIARY_IBAN=... \
//   G_BANK_SANDBOX_SMOKE_BENEFICIARY_NAME=... \
//   G_BANK_SANDBOX_SMOKE_REFERENCE=... \
//   node scripts/verify-truelayer-sandbox-e2e.js
//
// HARD BOUNDARY: aborts (no provider call) unless TRUELAYER_ENV=sandbox AND the
// resolved hosts are *.truelayer-sandbox.com AND G_BANK_ENABLE_LIVE!=true.
// Never prints secrets / tokens / private keys / PII.

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  executeVerified,
  reconcile,
  createAuthorization,
  SequenceStore,
  buildTrueLayerRegistry,
  buildTrueLayerPolicy,
  buildTrueLayerRequest,
  truelayerBindingSha256,
  checkResult,
} = require('../backend/g-verified-execution-spine');
const { TrueLayerLiveAdapter, endpoints, privateKeyPem } = require('../backend/g-bank-live-v1/providers/truelayer-live');
const { TrueLayerSpineConnector } = require('../backend/g-verified-execution-spine/connectors/truelayer-spine-connector');

const SCHEMA = 'g-truelayer-sandbox-e2e-evidence-v1';

function sha256(v) {
  return crypto.createHash('sha256').update(String(v == null ? '' : v)).digest('hex');
}
function gitCommit() {
  try {
    return require('node:child_process').execSync('git rev-parse HEAD', { cwd: path.resolve(__dirname, '..') }).toString().trim();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Phase 0 — hard sandbox boundary
// ---------------------------------------------------------------------------
function assertSandboxBoundary(env) {
  const tlEnv = String(env.TRUELAYER_ENV || '').toLowerCase();
  const ep = endpoints(env);
  const reasons = [];
  if (tlEnv !== 'sandbox') reasons.push(`TRUELAYER_ENV must be 'sandbox' (is '${tlEnv || 'unset'}')`);
  if (ep.live === true) reasons.push('resolved endpoints are PRODUCTION');
  if (!/truelayer-sandbox\.com$/.test(ep.authHost)) reasons.push(`auth host not sandbox: ${ep.authHost}`);
  if (!/truelayer-sandbox\.com$/.test(ep.apiHost)) reasons.push(`api host not sandbox: ${ep.apiHost}`);
  if (env.G_BANK_ENABLE_LIVE === 'true') reasons.push('G_BANK_ENABLE_LIVE=true is forbidden for a sandbox proof');
  return {
    ok: reasons.length === 0,
    reasons,
    target_environment: tlEnv === 'sandbox' && !ep.live ? 'SANDBOX' : 'PRODUCTION_OR_UNRESOLVED',
    auth_host: ep.authHost,
    api_host: ep.apiHost,
    production_payment_execution: 'DENY',
  };
}

// ---------------------------------------------------------------------------
// Phase 1 — redacted config preflight (presence / shape only)
// ---------------------------------------------------------------------------
function preflightConfig(env) {
  const present = (k) => Boolean(env[k] && String(env[k]).length > 0);
  const pk = privateKeyPem(env);
  let keyParsed = false;
  let keyCurve = null;
  let keyAlgOk = false;
  if (pk) {
    try {
      const ko = crypto.createPrivateKey(pk);
      keyParsed = true;
      keyCurve = ko.asymmetricKeyDetails ? ko.asymmetricKeyDetails.namedCurve || null : null;
      keyAlgOk = ko.asymmetricKeyType === 'ec' && keyCurve === 'secp521r1'; // ES512
    } catch {
      keyParsed = false;
    }
  }
  const returnUri = String(env.TRUELAYER_RETURN_URI || '');
  return {
    present: {
      TRUELAYER_CLIENT_ID: present('TRUELAYER_CLIENT_ID'),
      TRUELAYER_CLIENT_SECRET: present('TRUELAYER_CLIENT_SECRET'),
      TRUELAYER_SIGNING_KID: present('TRUELAYER_SIGNING_KID'),
      TRUELAYER_PRIVATE_KEY: present('TRUELAYER_PRIVATE_KEY_B64') ? 'B64' : present('TRUELAYER_PRIVATE_KEY_PEM') ? 'PEM' : 'ABSENT',
      TRUELAYER_RETURN_URI: present('TRUELAYER_RETURN_URI'),
      TRUELAYER_ENV: String(env.TRUELAYER_ENV || 'unset'),
      G_BANK_ENABLE_SANDBOX_EXTERNAL: env.G_BANK_ENABLE_SANDBOX_EXTERNAL === 'true',
      G_SPINE_AUTHORIZATION_SECRET: present('G_SPINE_AUTHORIZATION_SECRET'),
      sandbox_beneficiary_iban: present('G_BANK_SANDBOX_SMOKE_BENEFICIARY_IBAN'),
      sandbox_beneficiary_name: present('G_BANK_SANDBOX_SMOKE_BENEFICIARY_NAME'),
      sandbox_reference: present('G_BANK_SANDBOX_SMOKE_REFERENCE'),
    },
    signing_key_parsed: keyParsed,
    signing_key_curve: keyCurve,
    signing_alg_expected_es512: keyAlgOk,
    signing_kid_sha256: present('TRUELAYER_SIGNING_KID') ? sha256(env.TRUELAYER_SIGNING_KID) : null,
    client_id_sha256: present('TRUELAYER_CLIENT_ID') ? sha256(env.TRUELAYER_CLIENT_ID) : null,
    return_uri_shape_ok: /^https?:\/\/.+/.test(returnUri),
    return_uri_sha256: returnUri ? sha256(returnUri) : null,
    production_flag_G_BANK_ENABLE_LIVE: env.G_BANK_ENABLE_LIVE === 'true',
  };
}

// Structure probe: which key paths a provider object actually exposes.
function keyPaths(obj, prefix = '', out = []) {
  if (obj === null || typeof obj !== 'object') return out;
  for (const k of Object.keys(obj)) {
    const p = prefix ? `${prefix}.${k}` : k;
    out.push(p);
    if (obj[k] && typeof obj[k] === 'object' && !Array.isArray(obj[k])) keyPaths(obj[k], p, out);
  }
  return out;
}

function classifyBinding(readbackDetail) {
  if (!readbackDetail) return 'WEAK';
  const checks = readbackDetail.checks || {};
  const mismatch = readbackDetail.mismatch || [];
  if (mismatch.length > 0) return 'MISMATCH';
  const strongFields = ['payment_id', 'environment', 'amount', 'currency', 'beneficiary_iban', 'beneficiary_reference', 'intent_sha256', 'destination_binding'];
  return strongFields.every((f) => checks[f] === true) ? 'STRONG' : 'WEAK';
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function runE2E(options = {}) {
  const env = options.env || process.env;
  const evidenceDir = options.evidenceDir || env.G_BANK_E2E_EVIDENCE_DIR || '.secrets/evidence';
  const amountMinor = Number(options.amountMinor || env.G_BANK_E2E_SANDBOX_AMOUNT_MINOR || 100);
  const stateDir = options.stateDir || env.G_BANK_LIVE_STATE_DIR || '.secrets/g-truelayer-sandbox-e2e-state';
  const started = new Date().toISOString();

  const evidence = {
    schema: SCHEMA,
    timestamp: started,
    git_commit: gitCommit(),
    node_version: process.version,
    environment: null,
    boundary: null,
    config_preflight: null,
    oauth_verified: 'UNVERIFIED',
    signature_verified: 'UNVERIFIED',
    discover_result: null,
    schema_probe: null,
    payment_create_verified: 'UNVERIFIED',
    canonical_execution_state: null,
    provider_payment_id_sha256: null,
    execution_id: null,
    request_id: null,
    idempotency_key_sha256: null,
    canonical_request_sha256: null,
    receipt_sha256: null,
    audit_entry_hash: null,
    readback_verified: 'UNVERIFIED',
    binding_strength: 'UNVERIFIED',
    binding_fields_present: [],
    binding_fields_matched: [],
    binding_fields_mismatched: [],
    idempotency_verified: 'UNVERIFIED',
    reconcile_result: null,
    reconcile_nonexistent_result: null,
    assurance_level: null,
    audit_chain_verified: 'UNVERIFIED',
    provider_request_ids: [],
    assumptions: {
      A_get_payment_field_paths: 'UNVERIFIED',
      B_metadata_accepted_on_create: 'UNVERIFIED',
      C_metadata_returned_on_readback: 'UNVERIFIED',
      D_test_signature_success_status: 'UNVERIFIED',
      E_idempotent_replay_header_name: 'UNVERIFIED',
    },
    secrets_redacted: true,
    status: 'BLOCKED',
    abort_reason: null,
  };

  // ---- Phase 0 ----
  const boundary = assertSandboxBoundary(env);
  evidence.boundary = boundary;
  evidence.environment = boundary.target_environment;
  if (!boundary.ok) {
    evidence.status = 'BLOCKED';
    evidence.abort_reason = `SANDBOX BOUNDARY NOT SATISFIED — no provider call attempted: ${boundary.reasons.join('; ')}`;
    return finish(evidence, evidenceDir, options);
  }

  // ---- Phase 1 ----
  evidence.config_preflight = preflightConfig(env);
  const cp = evidence.config_preflight;
  const missing = Object.entries(cp.present).filter(([, v]) => v === false || v === 'ABSENT').map(([k]) => k);
  if (missing.length || !cp.signing_key_parsed || !cp.signing_alg_expected_es512 || !cp.return_uri_shape_ok) {
    evidence.status = 'BLOCKED';
    evidence.abort_reason = `config preflight incomplete: missing=[${missing.join(',')}] key_parsed=${cp.signing_key_parsed} es512=${cp.signing_alg_expected_es512} return_uri_ok=${cp.return_uri_shape_ok}`;
    return finish(evidence, evidenceDir, options);
  }

  const adapter = options.adapter || new TrueLayerLiveAdapter({ env });
  const connector = new TrueLayerSpineConnector({ adapter, env });

  // ---- Phase 2 — discover() ----
  let discovery;
  try {
    discovery = await connector.discover({ allowExternalEffects: true });
  } catch (err) {
    discovery = { ok: false, observed_assurance: 'L0', detail: `discover_threw:${err.message}` };
  }
  evidence.discover_result = discovery;
  if (discovery.ok === true) {
    evidence.oauth_verified = 'TRUE';
    evidence.signature_verified = 'TRUE';
    evidence.assumptions.D_test_signature_success_status = 'VERIFIED'; // 204 (adapter checks status === 204)
  } else {
    evidence.oauth_verified = discovery.detail && /preflight_failed|token/.test(discovery.detail) ? 'FALSE' : 'UNVERIFIED';
    evidence.signature_verified = 'FALSE';
    evidence.status = 'BLOCKED';
    evidence.abort_reason = `discover() failed: ${discovery.detail}`;
    return finish(evidence, evidenceDir, options);
  }

  // ---- Phase 4 — one sandbox payment via executeVerified() ----
  const actor = 'e2e:truelayer-sandbox';
  const idempotencyKey = `e2e-${crypto.randomUUID()}`;
  const seq = new SequenceStore(path.join(stateDir, 'sequence'));
  const stream = `${actor}::gbank.truelayer.payment`;
  const beneficiary = {
    iban: String(env.G_BANK_SANDBOX_SMOKE_BENEFICIARY_IBAN || ''),
    name: String(env.G_BANK_SANDBOX_SMOKE_BENEFICIARY_NAME || 'G-Bank Sandbox Beneficiary'),
    reference: String(env.G_BANK_SANDBOX_SMOKE_REFERENCE || 'GBANK-E2E').slice(0, 18),
  };
  const request = buildTrueLayerRequest({
    actor,
    requestId: `e2e-${idempotencyKey}`,
    idempotencyKey,
    expectedSequence: seq.current(stream) + 1,
    environment: 'sandbox',
    amountMinor,
    currency: 'EUR',
    beneficiary,
    user: {
      name: 'G-Bank Sandbox E2E',
      email: 'sandbox-e2e@g-bank.invalid',
      phone: '+310000000000',
      date_of_birth: '1990-01-01',
      address: { address_line1: 'Sandbox 1', city: 'Amsterdam', zip: '1011AA', country_code: 'NL' },
    },
    returnUri: String(env.TRUELAYER_RETURN_URI),
  });
  const bindingSha = truelayerBindingSha256(request);
  request.authorization_token = createAuthorization(
    {
      requestCanonicalSha256: bindingSha,
      idempotencyKey,
      actor,
      capability: request.requested_capability,
      operation: request.operation,
      ttl_seconds: 300,
    },
    env,
  );

  evidence.request_id = request.request_id;
  evidence.idempotency_key_sha256 = sha256(idempotencyKey);
  evidence.canonical_request_sha256 = bindingSha;

  const ctx = {
    env,
    stateDir,
    registry: buildTrueLayerRegistry({ adapter, env }),
    policy: buildTrueLayerPolicy({ actor, maxAmountMinor: Math.max(amountMinor, 100_00) }),
    allowExternalEffects: true,
  };

  const result = await executeVerified(request, ctx);
  evidence.canonical_execution_state = result.state;
  evidence.execution_id = result.execution_id || null;
  evidence.assurance_level = result.assurance_level_achieved || null;
  evidence.audit_entry_hash = result.audit_entry_hash || null;
  evidence.receipt_sha256 = result.result_sha256 || null;

  if (result.state !== 'VERIFIED_SUCCESS' && result.state !== 'READBACK_MISMATCH') {
    // Any provider effect that may have landed is quarantined by the spine.
    evidence.payment_create_verified = ['PROVIDER_FAILURE'].includes(result.state) ? 'FALSE' : 'UNVERIFIED';
    evidence.status = 'PARTIAL';
    evidence.abort_reason = `executeVerified => ${result.state} (${result.detail || ''})`;
    return finish(evidence, evidenceDir, options);
  }

  const providerPaymentId = result.provider_request_id;
  evidence.provider_payment_id_sha256 = providerPaymentId ? sha256(providerPaymentId) : null;
  if (providerPaymentId) evidence.provider_request_ids.push(sha256(providerPaymentId));
  evidence.payment_create_verified = providerPaymentId ? 'TRUE' : 'UNVERIFIED';

  // ---- Phase 3/5/8 — independent readback + schema probe ----
  let rawReadback = null;
  try {
    rawReadback = await adapter.getPayment(providerPaymentId);
  } catch (err) {
    rawReadback = { __error: err.message, provider_http_status: err.provider_http_status || null };
  }
  evidence.schema_probe = {
    get_payment_key_paths: rawReadback && !rawReadback.__error ? keyPaths(rawReadback).sort() : [],
    get_payment_error: rawReadback && rawReadback.__error ? rawReadback.__error : null,
  };
  evidence.assumptions.A_get_payment_field_paths = rawReadback && !rawReadback.__error ? 'VERIFIED' : 'UNVERIFIED';
  evidence.assumptions.C_metadata_returned_on_readback =
    rawReadback && !rawReadback.__error ? (rawReadback.metadata ? 'VERIFIED' : 'NOT_EXPOSED') : 'UNVERIFIED';

  // Connector-level readback with full binding classification.
  let rb = null;
  try {
    rb = await connector.readback(
      { params: request.params, binding_sha256: bindingSha },
      { provider_request_id: providerPaymentId },
    );
  } catch (err) {
    rb = { verified: false, binding_ok: false, detail: { error: err.message } };
  }
  const detail = (rb && rb.detail) || {};
  const checks = detail.checks || {};
  evidence.binding_fields_present = Object.keys(checks);
  evidence.binding_fields_matched = Object.keys(checks).filter((k) => checks[k] === true);
  evidence.binding_fields_mismatched = detail.mismatch || [];
  evidence.binding_strength = classifyBinding(detail);
  evidence.assumptions.B_metadata_accepted_on_create =
    checks.intent_sha256 === true || (rawReadback && rawReadback.metadata && rawReadback.metadata.g_intent_sha256) ? 'VERIFIED' : 'NOT_EXPOSED';

  if (evidence.binding_strength === 'MISMATCH' || result.state === 'READBACK_MISMATCH') {
    evidence.readback_verified = 'FALSE';
    evidence.status = 'PARTIAL';
    evidence.abort_reason = `readback binding MISMATCH: ${JSON.stringify(evidence.binding_fields_mismatched)}`;
    return finish(evidence, evidenceDir, options);
  }
  evidence.readback_verified = rb && rb.verified === true ? 'TRUE' : 'FALSE';

  // ---- Phase 6 — idempotency ----
  const replay = await executeVerified(request, ctx);
  const replayNoEffect =
    (replay.state === 'VERIFIED_SUCCESS' && replay.replayed === true) ||
    replay.state === 'REPLAY_REJECTED';
  evidence.idempotency_verified = replayNoEffect ? 'TRUE' : 'FALSE';
  evidence.idempotency_replay_state = replay.state;

  // ---- Phase 7 — reconciliation ----
  const rec = await reconcile(
    { idempotency_key: idempotencyKey, provider_request_id: providerPaymentId },
    { env, stateDir, registry: buildTrueLayerRegistry({ adapter, env }), capability: 'gbank.truelayer.payment' },
  );
  evidence.reconcile_result = rec.state;
  const nonexistentId = `00000000-0000-0000-0000-000000000000`;
  let recNx;
  try {
    recNx = await reconcile(
      { idempotency_key: `nonexistent-${crypto.randomUUID()}`, provider_request_id: nonexistentId },
      { env, stateDir, registry: buildTrueLayerRegistry({ adapter, env }), capability: 'gbank.truelayer.payment' },
    );
  } catch (err) {
    recNx = { state: `THREW:${err.message}` };
  }
  evidence.reconcile_nonexistent_result = recNx.state;

  // ---- audit chain ----
  try {
    const { ReceiptLedger } = require('../backend/g-bank-live-v1/receipt-ledger');
    evidence.audit_chain_verified = new ReceiptLedger(path.join(stateDir, 'audit.jsonl')).verify().valid ? 'TRUE' : 'FALSE';
  } catch {
    evidence.audit_chain_verified = 'UNVERIFIED';
  }

  // ---- overall status ----
  const l4 =
    result.state === 'VERIFIED_SUCCESS' &&
    evidence.binding_strength === 'STRONG' &&
    evidence.assurance_level === 'L4' &&
    evidence.readback_verified === 'TRUE' &&
    evidence.idempotency_verified === 'TRUE' &&
    evidence.reconcile_result === 'EFFECT_CONFIRMED' &&
    evidence.audit_chain_verified === 'TRUE';
  const l3 =
    result.state === 'VERIFIED_SUCCESS' &&
    evidence.payment_create_verified === 'TRUE' &&
    evidence.idempotency_verified === 'TRUE';
  evidence.status = l4 ? 'VERIFIED_L4' : l3 ? 'VERIFIED_L3' : 'PARTIAL';

  return finish(evidence, evidenceDir, options);
}

function finish(evidence, evidenceDir, options) {
  evidence.completed_at = new Date().toISOString();
  if (options.noWrite) return evidence;
  try {
    fs.mkdirSync(path.resolve(evidenceDir), { recursive: true, mode: 0o700 });
    const file = path.join(
      path.resolve(evidenceDir),
      `g-truelayer-sandbox-e2e-${evidence.timestamp.replace(/[:.]/g, '-')}.json`,
    );
    fs.writeFileSync(file, JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    evidence.evidence_file = file;
  } catch (err) {
    evidence.evidence_write_error = err.message;
  }
  return evidence;
}

module.exports = { runE2E, assertSandboxBoundary, preflightConfig, classifyBinding, SCHEMA };

if (require.main === module) {
  const args = process.argv.slice(2);
  const evIdx = args.indexOf('--evidence-dir');
  runE2E({ evidenceDir: evIdx >= 0 ? args[evIdx + 1] : undefined })
    .then((ev) => {
      // Print the receipt WITHOUT any secret material (it contains none).
      console.log(JSON.stringify(ev, null, 2));
      console.log(`\nG_TRUELAYER_SANDBOX_E2E_STATUS = ${ev.status}`);
      process.exit(ev.status === 'VERIFIED_L4' || ev.status === 'VERIFIED_L3' ? 0 : 1);
    })
    .catch((err) => {
      console.error('E2E_RUNNER_ERROR =', err && err.message ? err.message : String(err));
      process.exit(2);
    });
}
