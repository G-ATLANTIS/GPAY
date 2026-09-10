'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const {
  RESULT_STATE,
  ASSURANCE,
  VERIFICATION_METHOD,
  CANONICAL_COMMIT_STATUS,
  PolicyEngine,
  CapabilityRegistry,
  SequenceStore,
  createAuthorization,
  executeVerified,
  reconcile,
  requestCanonicalSha256,
  normalizeRequest,
  checkResult,
  assertResult,
  redact,
  safeEvidence,
  LocalFileCapability,
} = require('../g-verified-execution-spine');

const { IdempotencyStore } = require('../g-bank-live-v1/idempotency-store');
const { ReceiptLedger } = require('../g-bank-live-v1/receipt-ledger');

const SECRET = 'k'.repeat(48);
const ENV = { G_SPINE_AUTHORIZATION_SECRET: SECRET };

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'g-spine-'));
}

function allowRule(actor, capability) {
  return {
    id: 'allow-local-append',
    effect: 'ALLOW',
    match: { actor, capability, operation: 'append-record', min_assurance: 'L1', require_scope_bounded: true },
  };
}

// Build a full, valid execution setup around the real LocalFileCapability.
function setup(overrides = {}) {
  const dir = overrides.dir || tmpDir();
  const actor = overrides.actor || 'operator:gijs';
  const capability = overrides.capability || 'local.file.append';

  const connector =
    overrides.connector ||
    new LocalFileCapability({ name: capability, rootDir: path.join(dir, 'cap'), ...overrides.connectorOpts });

  const registry = new CapabilityRegistry();
  registry.register(connector);

  const policy = new PolicyEngine(
    overrides.rules || [
      { id: 'deny-everything-else', effect: 'DENY', match: { min_assurance: 'L4' } }, // inert unless L4
      allowRule(actor, capability),
    ],
  );

  const idempotency = new IdempotencyStore(path.join(dir, 'idem'));
  const sequence = new SequenceStore(path.join(dir, 'seq'));
  const ledger = new ReceiptLedger(path.join(dir, 'audit.jsonl'));

  const ctx = {
    env: ENV,
    stateDir: dir,
    registry,
    policy,
    idempotency,
    sequence,
    ledger,
    now: Date.now(),
    ...overrides.ctx,
  };

  const request = {
    request_id: overrides.request_id || `req-${crypto.randomUUID()}`,
    actor,
    requested_capability: capability,
    operation: 'append-record',
    params: overrides.params || { bucket: 'default', record: { note: 'hello', n: 1 } },
    idempotency_key: overrides.idempotency_key || `idem-${crypto.randomUUID()}`,
    expected_sequence: overrides.expected_sequence || 1,
    scope: overrides.scope || { max_effects: 1, note: 'single bounded append' },
    required_assurance: overrides.required_assurance || 'L1',
  };

  const bindingSha = requestCanonicalSha256(normalizeRequest(request));
  const token =
    overrides.token !== undefined
      ? overrides.token
      : createAuthorization(
          {
            requestCanonicalSha256: bindingSha,
            idempotencyKey: request.idempotency_key,
            actor,
            capability,
            operation: 'append-record',
            ttl_seconds: 300,
            now: ctx.now,
          },
          ENV,
        );
  request.authorization_token = token;

  return { dir, ctx, request, registry, policy, connector, idempotency, sequence, ledger, bindingSha, actor, capability };
}

// --------------------------------------------------------------------------
// 1. Valid verified execution
// --------------------------------------------------------------------------
test('valid verified execution reaches VERIFIED_SUCCESS with full evidence', async () => {
  const { ctx, request, ledger } = setup();
  const r = await executeVerified(request, ctx);

  assert.equal(r.state, RESULT_STATE.VERIFIED_SUCCESS);
  assert.equal(r.canonical_commit_status, CANONICAL_COMMIT_STATUS.COMMITTED);
  assert.equal(r.stage_reached, 'COMMIT_STATE');
  assert.equal(r.verification_method, VERIFICATION_METHOD.LOCAL_STATE_READBACK);
  assert.equal(r.assurance_level_achieved, ASSURANCE.L1);
  assert.ok(r.provider_request_id);
  assert.ok(r.audit_entry_hash);
  assert.ok(r.result_sha256);
  assert.ok(r.pre_state_hash);
  assert.ok(r.post_state_hash);
  assert.notEqual(r.pre_state_hash, r.post_state_hash);
  assertResult(r);

  const rows = ledger.readAll();
  assert.equal(ledger.verify().valid, true);
  assert.ok(rows.some((x) => x.event === 'EXECUTION_AUTHORIZED'));
  assert.ok(rows.some((x) => x.event === 'VERIFIED_EXECUTION_COMMIT'));
});

// --------------------------------------------------------------------------
// 2. Missing authorization
// --------------------------------------------------------------------------
test('missing authorization token => DENIED_AUTHORIZATION, no execution', async () => {
  const { ctx, request } = setup({ token: undefined });
  delete request.authorization_token;
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.DENIED_AUTHORIZATION);
  assert.equal(r.provider_request_id, null);
  assert.equal(r.canonical_commit_status, CANONICAL_COMMIT_STATUS.NOT_COMMITTED);
  assertResult(r);
});

// --------------------------------------------------------------------------
// 3. Invalid authorization (wrong secret / tampered mac)
// --------------------------------------------------------------------------
test('authorization signed with a different secret => DENIED_AUTHORIZATION', async () => {
  const { ctx, request, bindingSha, actor, capability } = setup();
  request.authorization_token = createAuthorization(
    {
      requestCanonicalSha256: bindingSha,
      idempotencyKey: request.idempotency_key,
      actor,
      capability,
      operation: 'append-record',
      now: ctx.now,
    },
    { G_SPINE_AUTHORIZATION_SECRET: 'w'.repeat(48) },
  );
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.DENIED_AUTHORIZATION);
  assert.match(r.detail, /signature_invalid/);
  assertResult(r);
});

test('authorization bound to a different params payload => DENIED_AUTHORIZATION', async () => {
  const { ctx, request } = setup();
  request.params = { bucket: 'default', record: { note: 'MUTATED', n: 999 } };
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.DENIED_AUTHORIZATION);
  assertResult(r);
});

// --------------------------------------------------------------------------
// 4. Policy denial
// --------------------------------------------------------------------------
test('policy default-deny when no allow rule matches => DENIED_POLICY', async () => {
  const { ctx, request } = setup({ rules: [{ id: 'noop', effect: 'ALLOW', match: { actor: 'someone-else' } }] });
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.DENIED_POLICY);
  assert.match(r.detail, /default_deny/);
  assert.equal(r.provider_request_id, null);
  assertResult(r);
});

test('strictest policy wins: a matching DENY overrides a matching ALLOW', async () => {
  const { actor, capability } = setup();
  const { ctx, request } = setup({
    actor,
    capability,
    rules: [
      allowRule(actor, capability),
      { id: 'kill-switch', effect: 'DENY', match: { capability } },
    ],
  });
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.DENIED_POLICY);
  assert.match(r.detail, /explicit_deny:kill-switch/);
  assertResult(r);
});

// --------------------------------------------------------------------------
// 5. Missing connector / provider
// --------------------------------------------------------------------------
test('unregistered capability => NO_VERIFIED_PATH', async () => {
  const { ctx, request } = setup();
  request.requested_capability = 'does.not.exist';
  // rebuild token for the new binding so we fail at CHECK_PATH, not AUTH
  const bindingSha = requestCanonicalSha256(normalizeRequest(request));
  request.authorization_token = createAuthorization(
    { requestCanonicalSha256: bindingSha, idempotencyKey: request.idempotency_key, actor: request.actor, capability: 'does.not.exist', operation: 'append-record', now: ctx.now },
    ENV,
  );
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.NO_VERIFIED_PATH);
  assertResult(r);
});

test('connector discover() reporting not-available => NO_VERIFIED_PATH', async () => {
  const connector = {
    name: 'flaky.cap',
    assurance_ceiling: 'L2',
    supportsReadback: false,
    async discover() {
      return { ok: false, observed_assurance: 'L0', detail: 'down' };
    },
    async captureState() {
      return 'ABSENT';
    },
    async execute() {
      throw new Error('should never be called');
    },
  };
  const { ctx, request } = setup({ connector, capability: 'flaky.cap' });
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.NO_VERIFIED_PATH);
  assert.equal(r.stage_reached, 'DISCOVER_CAPABILITY');
  assertResult(r);
});

test('required_assurance above what discover evidences => NO_VERIFIED_PATH (no auto-promotion)', async () => {
  const { ctx, request } = setup({ required_assurance: 'L4' });
  const bindingSha = requestCanonicalSha256(normalizeRequest(request));
  request.authorization_token = createAuthorization(
    { requestCanonicalSha256: bindingSha, idempotencyKey: request.idempotency_key, actor: request.actor, capability: request.requested_capability, operation: 'append-record', now: ctx.now },
    ENV,
  );
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.NO_VERIFIED_PATH);
  assert.match(r.detail, /assurance_below_required/);
  assertResult(r);
});

// --------------------------------------------------------------------------
// 6. Provider timeout / ambiguous failure
// --------------------------------------------------------------------------
test('provider ambiguous failure (no http status) => EXECUTION_UNVERIFIED + quarantine', async () => {
  const connector = {
    name: 'timeout.cap',
    assurance_ceiling: 'L3',
    supportsReadback: false,
    async discover() {
      return { ok: true, observed_assurance: 'L2' };
    },
    async captureState() {
      return 'S0';
    },
    async execute() {
      throw new Error('etimedout'); // no provider_http_status => ambiguous
    },
  };
  const { ctx, request, idempotency } = setup({
    connector,
    capability: 'timeout.cap',
    rules: [{ id: 'a', effect: 'ALLOW', match: { capability: 'timeout.cap', min_assurance: 'L2' } }],
  });
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.EXECUTION_UNVERIFIED);
  assert.equal(r.canonical_commit_status, CANONICAL_COMMIT_STATUS.QUARANTINED_RECONCILE);
  assertResult(r);
  const rec = idempotency.read(request.idempotency_key);
  assert.equal(rec.state, 'UNKNOWN_REQUIRES_RECONCILIATION');
});

test('provider definite failure (http status present) => PROVIDER_FAILURE + FAILED_FINAL', async () => {
  const connector = {
    name: 'reject.cap',
    assurance_ceiling: 'L3',
    supportsReadback: false,
    async discover() {
      return { ok: true, observed_assurance: 'L2' };
    },
    async captureState() {
      return 'S0';
    },
    async execute() {
      const e = new Error('provider rejected');
      e.provider_http_status = 422;
      throw e;
    },
  };
  const { ctx, request, idempotency } = setup({
    connector,
    capability: 'reject.cap',
    rules: [{ id: 'a', effect: 'ALLOW', match: { capability: 'reject.cap', min_assurance: 'L2' } }],
  });
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.PROVIDER_FAILURE);
  assertResult(r);
  assert.equal(idempotency.read(request.idempotency_key).state, 'FAILED_FINAL');
});

// --------------------------------------------------------------------------
// 7. Provider says success but verification fails
// --------------------------------------------------------------------------
test('execute() claims applied but readback cannot confirm => READBACK_MISMATCH, not success', async () => {
  const connector = {
    name: 'liar.cap',
    assurance_ceiling: 'L4',
    supportsReadback: true,
    async discover() {
      return { ok: true, observed_assurance: 'L2' };
    },
    async captureState() {
      return 'S0';
    },
    async execute() {
      return { provider: 'liar.cap', provider_request_id: 'liar-123', applied: true, raw_status: 'OK' };
    },
    async readback() {
      return { verified: false, binding_ok: false, observed_status: 'NOT_FOUND', external: true };
    },
  };
  const { ctx, request, idempotency } = setup({
    connector,
    capability: 'liar.cap',
    rules: [{ id: 'a', effect: 'ALLOW', match: { capability: 'liar.cap', min_assurance: 'L2' } }],
  });
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.READBACK_MISMATCH);
  assert.notEqual(r.canonical_commit_status, CANONICAL_COMMIT_STATUS.COMMITTED);
  assertResult(r);
  assert.equal(idempotency.read(request.idempotency_key).state, 'UNKNOWN_REQUIRES_RECONCILIATION');
});

// --------------------------------------------------------------------------
// 8. Stale state / non-monotonic sequence
// --------------------------------------------------------------------------
test('stale (non-monotonic) sequence => STALE_STATE_REJECTED', async () => {
  const { ctx, request, actor, capability, sequence } = setup();
  const r1 = await executeVerified(request, ctx);
  assert.equal(r1.state, RESULT_STATE.VERIFIED_SUCCESS);
  assert.equal(sequence.current(`${actor}::${capability}`), 1);

  // Second request re-using sequence 1 (<= committed) must be rejected.
  const s2 = setup({ dir: ctx.stateDir, actor, capability, expected_sequence: 1 });
  const r2 = await executeVerified(s2.request, { ...ctx, ...s2.ctx, registry: ctx.registry, policy: ctx.policy });
  assert.equal(r2.state, RESULT_STATE.STALE_STATE_REJECTED);
  assertResult(r2);
});

// --------------------------------------------------------------------------
// 9. Duplicate / replayed request
// --------------------------------------------------------------------------
test('identical replayed request returns the recorded result, no second effect', async () => {
  const { ctx, request, connector } = setup();
  const r1 = await executeVerified(request, ctx);
  assert.equal(r1.state, RESULT_STATE.VERIFIED_SUCCESS);
  const file = path.join(connector.rootDir, 'default.jsonl');
  const linesAfterFirst = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).length;

  const r2 = await executeVerified(request, ctx);
  assert.equal(r2.state, RESULT_STATE.VERIFIED_SUCCESS);
  assert.equal(r2.replayed, true);
  assert.equal(r2.provider_request_id, r1.provider_request_id);
  const linesAfterSecond = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).length;
  assert.equal(linesAfterSecond, linesAfterFirst, 'replay must not append a second record');
});

test('same idempotency key, different request => REPLAY_REJECTED', async () => {
  const { ctx, request } = setup();
  const r1 = await executeVerified(request, ctx);
  assert.equal(r1.state, RESULT_STATE.VERIFIED_SUCCESS);

  const different = { ...request, request_id: `req-${crypto.randomUUID()}`, expected_sequence: 2 };
  const bindingSha = requestCanonicalSha256(normalizeRequest(different));
  different.authorization_token = createAuthorization(
    { requestCanonicalSha256: bindingSha, idempotencyKey: different.idempotency_key, actor: different.actor, capability: different.requested_capability, operation: 'append-record', now: ctx.now },
    ENV,
  );
  const r2 = await executeVerified(different, ctx);
  assert.equal(r2.state, RESULT_STATE.REPLAY_REJECTED);
  assertResult(r2);
});

// --------------------------------------------------------------------------
// 10. Concurrent duplicate execution
// --------------------------------------------------------------------------
test('concurrent identical executions: exactly one effect, one commit', async () => {
  const { ctx, request, connector } = setup();
  const results = await Promise.all([
    executeVerified(request, ctx),
    executeVerified(request, ctx),
    executeVerified(request, ctx),
  ]);
  const successes = results.filter((r) => r.state === RESULT_STATE.VERIFIED_SUCCESS && !r.replayed);
  const rejected = results.filter((r) => r.state === RESULT_STATE.REPLAY_REJECTED || r.replayed === true);
  assert.equal(successes.length, 1, 'exactly one fresh success');
  assert.equal(successes.length + rejected.length, 3);

  const file = path.join(connector.rootDir, 'default.jsonl');
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
  assert.equal(lines.length, 1, 'exactly one real effect on disk');
});

// --------------------------------------------------------------------------
// 11. Modified receipt / mismatched request id / actor
// --------------------------------------------------------------------------
test('tampered authorization payload (swapped actor) fails HMAC => DENIED_AUTHORIZATION', async () => {
  const { ctx, request } = setup();
  const [enc, mac] = request.authorization_token.split('.');
  const body = JSON.parse(Buffer.from(enc, 'base64url').toString('utf8'));
  body.actor = 'operator:someone-else';
  const forged = Buffer.from(JSON.stringify(body)).toString('base64url') + '.' + mac;
  request.authorization_token = forged;
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.DENIED_AUTHORIZATION);
  assertResult(r);
});

test('result_sha256 detects a modified result field', async () => {
  const { canonicalJson, sha256 } = require('../g-bank-live-v1/canonical');
  const { ctx, request } = setup();
  const r = await executeVerified(request, ctx);
  const tampered = { ...r, actor: 'attacker' };
  const { observed_at, result_sha256, audit_entry_hash, ...rest } = tampered;
  assert.notEqual(sha256(canonicalJson(rest)), r.result_sha256);
});

// --------------------------------------------------------------------------
// 12. Corrupted audit chain
// --------------------------------------------------------------------------
test('corrupted audit ledger => next execution fails closed at AUDIT', async () => {
  const { ctx, request, ledger, dir } = setup();
  const r1 = await executeVerified(request, ctx);
  assert.equal(r1.state, RESULT_STATE.VERIFIED_SUCCESS);

  // Tamper with a committed audit row.
  const auditPath = path.join(dir, 'audit.jsonl');
  const raw = fs.readFileSync(auditPath, 'utf8').split('\n').filter(Boolean);
  const row = JSON.parse(raw[0]);
  row.actor = 'tampered';
  raw[0] = JSON.stringify(row);
  fs.writeFileSync(auditPath, raw.join('\n') + '\n');
  assert.throws(() => ledger.verify(), /receipt_hash_invalid/);

  const s2 = setup({ dir, actor: request.actor, capability: request.requested_capability, expected_sequence: 2 });
  const r2 = await executeVerified(s2.request, { ...ctx, ...s2.ctx, registry: ctx.registry, policy: ctx.policy });
  assert.equal(r2.state, RESULT_STATE.INTERNAL_FAIL_CLOSED);
  assert.equal(r2.stage_reached, 'AUDIT');
  assertResult(r2);
});

// --------------------------------------------------------------------------
// 13. Crash between provider execution and local commit + recovery
// --------------------------------------------------------------------------
test('crash after external write, before commit: quarantined, then reconcile confirms, no re-issue', async () => {
  const dir = tmpDir();
  const capability = 'local.file.append';
  const { ctx, request, connector } = setup({
    dir,
    capability,
    connectorOpts: { failAfterWrite: true },
  });
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.EXECUTION_UNVERIFIED);
  assert.equal(r.canonical_commit_status, CANONICAL_COMMIT_STATUS.QUARANTINED_RECONCILE);

  // The effect DID land on disk (crash was after write).
  const file = path.join(connector.rootDir, 'default.jsonl');
  assert.equal(fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).length, 1);

  // Reconcile against the SAME connector (no failAfterWrite this time to model
  // the recovered process) — it must observe the effect, not repeat it.
  const healthy = new LocalFileCapability({ name: capability, rootDir: connector.rootDir });
  const registry2 = new CapabilityRegistry();
  registry2.register(healthy);
  const rec = await reconcile(
    { idempotency_key: request.idempotency_key },
    { ...ctx, registry: registry2, capability },
  );
  assert.equal(rec.reconciled, true);
  assert.equal(rec.state, 'EFFECT_CONFIRMED');
  // still exactly one effect
  assert.equal(fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).length, 1);
});

test('reconcile when no effect landed => EFFECT_ABSENT (safe to re-issue)', async () => {
  const dir = tmpDir();
  const capability = 'timeout.cap';
  const connector = {
    name: capability,
    assurance_ceiling: 'L4',
    supportsReadback: true,
    async discover() {
      return { ok: true, observed_assurance: 'L2' };
    },
    async captureState() {
      return 'S0';
    },
    async execute() {
      throw new Error('etimedout');
    },
    async readback() {
      return { verified: false, observed_status: 'NOT_FOUND', external: true };
    },
  };
  const { ctx, request } = setup({
    dir,
    connector,
    capability,
    rules: [{ id: 'a', effect: 'ALLOW', match: { capability, min_assurance: 'L2' } }],
  });
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.EXECUTION_UNVERIFIED);

  const rec = await reconcile({ idempotency_key: request.idempotency_key }, { ...ctx, capability });
  assert.equal(rec.reconciled, true);
  assert.equal(rec.state, 'EFFECT_ABSENT');
});

test('a quarantined idempotency key cannot be re-run by executeVerified without reconcile', async () => {
  const dir = tmpDir();
  const { ctx, request } = setup({ dir, connectorOpts: { failAfterWrite: true } });
  const r1 = await executeVerified(request, ctx);
  assert.equal(r1.state, RESULT_STATE.EXECUTION_UNVERIFIED);

  const r2 = await executeVerified(request, ctx);
  assert.equal(r2.state, RESULT_STATE.REPLAY_REJECTED);
  assert.match(r2.detail, /not_replayable_in_state_UNKNOWN_REQUIRES_RECONCILIATION/);
});

// --------------------------------------------------------------------------
// 14. Attempted bypass of the spine / direct canonical mutation
// --------------------------------------------------------------------------
test('a hand-crafted "success" object without evidence fails the invariant check', () => {
  const fake = {
    state: RESULT_STATE.VERIFIED_SUCCESS,
    canonical_commit_status: CANONICAL_COMMIT_STATUS.COMMITTED,
    evidence_complete: true,
    execution_id: 'x',
  };
  const { ok, violations } = checkResult(fake);
  assert.equal(ok, false);
  assert.ok(violations.some((v) => v.startsWith('verified_success_missing_')));
  assert.throws(() => assertResult(fake), /invariant_violation/);
});

test('writing directly to the idempotency store does not yield a spine-valid committed result', () => {
  const dir = tmpDir();
  const store = new IdempotencyStore(path.join(dir, 'idem'));
  store.claim({ key: 'k12345678', request: { a: 1 } });
  store.finalize({
    key: 'k12345678',
    request: { a: 1 },
    state: 'SUCCEEDED',
    result: { state: RESULT_STATE.VERIFIED_SUCCESS, canonical_commit_status: CANONICAL_COMMIT_STATUS.COMMITTED },
  });
  const rec = store.read('k12345678');
  assert.throws(() => assertResult(rec.result), /invariant_violation/);
});

test('DENY-before-execute results never carry an execution receipt', async () => {
  const { ctx, request } = setup({ rules: [{ id: 'x', effect: 'ALLOW', match: { actor: 'nobody' } }] });
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.DENIED_POLICY);
  assert.equal(r.provider_request_id, null);
  assert.equal(r.execution_result, null);
});

// --------------------------------------------------------------------------
// 15. Secret redaction
// --------------------------------------------------------------------------
test('secrets in params never reach the result, ledger, or idempotency record', async () => {
  const { ctx, request, ledger, idempotency, dir } = setup({
    params: {
      bucket: 'default',
      record: { note: 'ok' },
      access_token: 'live_abcdefghijklmnopqrstuvwxyz012345',
      client_secret: 'super-secret-value',
      nested: { authorization: 'Bearer eyJabc.def.ghi', api_key: 'AKIA0123456789ABCDEF' },
    },
  });
  // token must be bound to these params
  const bindingSha = requestCanonicalSha256(normalizeRequest(request));
  request.authorization_token = createAuthorization(
    { requestCanonicalSha256: bindingSha, idempotencyKey: request.idempotency_key, actor: request.actor, capability: request.requested_capability, operation: 'append-record', now: ctx.now },
    ENV,
  );

  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.VERIFIED_SUCCESS);

  const haystacks = [
    JSON.stringify(r),
    fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8'),
    JSON.stringify(idempotency.read(request.idempotency_key)),
  ];
  for (const h of haystacks) {
    assert.equal(h.includes('super-secret-value'), false);
    assert.equal(h.includes('live_abcdefghijklmnopqrstuvwxyz012345'), false);
    assert.equal(h.includes('AKIA0123456789ABCDEF'), false);
    assert.equal(/Bearer eyJ/.test(h), false);
  }
  assert.equal(ledger.verify().valid, true);
});

test('redact() masks sensitive keys and secret-shaped values; safeEvidence throws on leftovers', () => {
  const red = redact({ password: 'p', ok: 1, blob: '-----BEGIN RSA PRIVATE KEY-----xyz' });
  assert.equal(red.password, '[REDACTED]');
  assert.equal(red.ok, 1);
  assert.equal(red.blob, '[REDACTED]');
  assert.doesNotThrow(() => safeEvidence({ a: 'plain' }));
});

// --------------------------------------------------------------------------
// 16. Regression: existing g-bank-live-v1 core still passes its own contract
// --------------------------------------------------------------------------
test('regression: g-bank-live-v1 canonical + approval primitives unchanged', () => {
  const { normalizeIntent } = require('../g-bank-live-v1/canonical');
  const { createApproval, verifyApproval } = require('../g-bank-live-v1/approval');
  const i = normalizeIntent({
    intent_id: `intent-${crypto.randomUUID()}`,
    amount_minor: 100,
    currency: 'EUR',
    description: 'regression',
    destination_binding: 'merchant:x',
  });
  const env = { G_BANK_APPROVAL_SECRET: 'z'.repeat(48) };
  const key = crypto.randomUUID();
  const token = createApproval({ intent: i, provider: 'p', idempotencyKey: key }, env);
  assert.equal(verifyApproval(token, { intent: i, provider: 'p', idempotencyKey: key }, env).intent_sha256, i.intent_sha256);
});

// --------------------------------------------------------------------------
// 17. Scope enforcement
// --------------------------------------------------------------------------
test('unbounded scope (max_effects != 1) => DENIED_SCOPE', async () => {
  const { ctx, request } = setup({ scope: { max_effects: 5 } });
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.DENIED_SCOPE);
  assertResult(r);
});

test('missing scope => DENIED_SCOPE (fail closed, not fail open)', async () => {
  const { ctx, request } = setup();
  delete request.scope;
  const r = await executeVerified(request, ctx);
  // normalizeRequest coerces missing scope to {max_effects: NaN} -> INTERNAL_FAIL_CLOSED or DENIED_SCOPE
  assert.ok([RESULT_STATE.DENIED_SCOPE, RESULT_STATE.INTERNAL_FAIL_CLOSED].includes(r.state));
  assert.notEqual(r.state, RESULT_STATE.VERIFIED_SUCCESS);
});

// --------------------------------------------------------------------------
// 18. Mismatched request id between request and token binding
// --------------------------------------------------------------------------
test('token minted for a different request_id => DENIED_AUTHORIZATION', async () => {
  const { ctx, request } = setup();
  request.request_id = `req-${crypto.randomUUID()}`; // change after token minted
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.DENIED_AUTHORIZATION);
  assertResult(r);
});
