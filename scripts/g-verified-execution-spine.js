#!/usr/bin/env node
'use strict';

// Guarded CLI for the G_VERIFIED_EXECUTION_SPINE.
//
//   node scripts/g-verified-execution-spine.js self-check
//       Runs the runtime invariant checks against representative results and
//       exits non-zero on any violation. No side effects.
//
//   node scripts/g-verified-execution-spine.js demo-local <stateDir>
//       Drives ONE real, bounded, harmless local append through the full
//       pipeline (no network, no value movement) and prints the
//       VerifiedExecutionResult. Requires G_SPINE_AUTHORIZATION_SECRET.
//
//   node scripts/g-verified-execution-spine.js verify-audit <audit.jsonl>
//       Verifies a hash-chained audit ledger.
//
// This CLI cannot perform an external financial effect. The Mollie connector is
// intentionally not wired here.

const path = require('node:path');
const crypto = require('node:crypto');
const { ReceiptLedger } = require('../backend/g-bank-live-v1/receipt-ledger');
const {
  RESULT_STATE,
  CANONICAL_COMMIT_STATUS,
  PolicyEngine,
  CapabilityRegistry,
  createAuthorization,
  executeVerified,
  normalizeRequest,
  requestCanonicalSha256,
  checkResult,
  LocalFileCapability,
} = require('../backend/g-verified-execution-spine');

function die(msg, code = 2) {
  console.error(msg);
  process.exit(code);
}

async function selfCheck() {
  const cases = [
    { name: 'bare-success-missing-evidence', result: { state: RESULT_STATE.VERIFIED_SUCCESS, canonical_commit_status: CANONICAL_COMMIT_STATUS.COMMITTED, evidence_complete: true }, expectOk: false },
    { name: 'committed-without-success', result: { state: RESULT_STATE.EXECUTION_UNVERIFIED, canonical_commit_status: CANONICAL_COMMIT_STATUS.COMMITTED }, expectOk: false },
    { name: 'denied-with-receipt', result: { state: RESULT_STATE.DENIED_POLICY, provider_request_id: 'x' }, expectOk: false },
    { name: 'clean-denial', result: { state: RESULT_STATE.DENIED_POLICY, canonical_commit_status: CANONICAL_COMMIT_STATUS.NOT_COMMITTED }, expectOk: true },
  ];
  let failed = 0;
  for (const c of cases) {
    const { ok } = checkResult(c.result);
    const pass = ok === c.expectOk;
    console.log(`${pass ? 'PASS' : 'FAIL'}  ${c.name} (ok=${ok}, expected=${c.expectOk})`);
    if (!pass) failed += 1;
  }
  if (failed) die(`self-check FAILED: ${failed} case(s)`, 1);
  console.log('self-check: PASS');
}

async function demoLocal(stateDir) {
  if (!stateDir) die('usage: demo-local <stateDir>');
  if (Buffer.byteLength(String(process.env.G_SPINE_AUTHORIZATION_SECRET || '')) < 32) {
    die('G_SPINE_AUTHORIZATION_SECRET (>=32 bytes) required in the environment');
  }
  const root = path.resolve(stateDir);
  const actor = 'cli:demo';
  const capability = 'local.file.append';

  const registry = new CapabilityRegistry();
  registry.register(new LocalFileCapability({ name: capability, rootDir: path.join(root, 'cap') }));
  const policy = new PolicyEngine([
    { id: 'demo-allow', effect: 'ALLOW', match: { actor, capability, operation: 'append-record', min_assurance: 'L1', require_scope_bounded: true } },
  ]);

  const now = Date.now();
  const request = {
    request_id: `cli-${crypto.randomUUID()}`,
    actor,
    requested_capability: capability,
    operation: 'append-record',
    params: { bucket: 'demo', record: { source: 'cli demo-local', at: new Date(now).toISOString() } },
    idempotency_key: `cli-${crypto.randomUUID()}`,
    expected_sequence: 1,
    scope: { max_effects: 1, note: 'cli bounded demo' },
    required_assurance: 'L1',
  };
  const binding = requestCanonicalSha256(normalizeRequest(request));
  request.authorization_token = createAuthorization(
    { requestCanonicalSha256: binding, idempotencyKey: request.idempotency_key, actor, capability, operation: 'append-record', now },
    process.env,
  );

  const result = await executeVerified(request, { env: process.env, stateDir: root, registry, policy, now });
  console.log(JSON.stringify(result, null, 2));
  const { ok, violations } = checkResult(result);
  console.log(`INVARIANTS_OK = ${ok}`);
  if (!ok) die(`invariant violations: ${violations.join(';')}`, 1);
  if (result.state !== RESULT_STATE.VERIFIED_SUCCESS) die(`demo did not verify: ${result.state} (${result.detail})`, 1);
}

function verifyAudit(file) {
  if (!file) die('usage: verify-audit <audit.jsonl>');
  const ledger = new ReceiptLedger(path.resolve(file));
  console.log(JSON.stringify(ledger.verify(), null, 2));
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  if (cmd === 'self-check') return selfCheck();
  if (cmd === 'demo-local') return demoLocal(args[0]);
  if (cmd === 'verify-audit') return verifyAudit(args[0]);
  die('commands: self-check | demo-local <stateDir> | verify-audit <audit.jsonl>');
}

main().catch((err) => {
  console.error('G_VERIFIED_EXECUTION_SPINE_CLI_ERROR =', err && err.message ? err.message : String(err));
  process.exit(2);
});
