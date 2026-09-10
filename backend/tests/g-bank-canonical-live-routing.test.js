'use strict';

// G-BANK-CANONICAL-LIVE-ROUTING-P0
//
// Every live Mollie mutation goes through executeVerified() + MollieSpineConnector.
// These tests drive that path with an injected fake adapter (no network, no value
// movement) and assert the routing / binding / crash-recovery guarantees.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const { normalizeIntent, sha256 } = require('../g-bank-live-v1/canonical');
const { MollieLiveAdapter } = require('../g-bank-live-v1/providers/mollie-live');
const { GBankLiveCore } = require('../g-bank-live-v1/live-core');
const {
  executeVerified,
  reconcile,
  createAuthorization,
  assertResult,
  RESULT_STATE,
  ASSURANCE,
  VERIFICATION_METHOD,
  getExecutionTruth,
  buildMollieRegistry,
  buildMolliePolicy,
  buildMollieRequest,
  mollieBindingSha256,
} = require('../g-verified-execution-spine');
const { IdempotencyStore } = require('../g-bank-live-v1/idempotency-store');
const { ReceiptLedger } = require('../g-bank-live-v1/receipt-ledger');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-routing-'));
}

function liveEnv(extra = {}) {
  return {
    G_BANK_ENABLE_LIVE: 'true',
    G_BANK_EXTERNAL_ACTIONS_ENABLED: 'true',
    G_BANK_SIMULATED_LIVE_SUCCESS: 'false',
    G_SPINE_AUTHORIZATION_SECRET: 'k'.repeat(48),
    ...extra,
  };
}

function makeIntent(over = {}) {
  return normalizeIntent({
    intent_id: `intent-${crypto.randomUUID()}`,
    amount_minor: 1234,
    currency: 'EUR',
    description: 'routing test payment',
    destination_binding: 'mollie-profile:test',
    redirect_url: 'https://example.test/return',
    webhook_url: 'https://example.test/webhook',
    metadata: { order: 'ORD-1' },
    ...over,
  });
}

// Fake that mirrors MollieLiveAdapter's surface. No network.
class FakeMollieAdapter {
  constructor(opts = {}) {
    this.opts = opts;
    this.createCount = 0;
    this.getCount = 0;
    this._store = new Map(); // payment_id -> record
  }

  async preflight() {
    if (this.opts.preflightFail) {
      const e = new Error('mollie_live_preflight_failed');
      e.provider_http_status = 401;
      throw e;
    }
    return { provider: 'mollie-live', environment: 'LIVE', authenticated: true, provider_http_status: 200, enabled_methods: ['ideal'] };
  }

  async createPayment({ intent, idempotencyKey }) {
    this.createCount += 1;
    const paymentId = `tr_${crypto.randomBytes(6).toString('hex')}`;
    const record = {
      payment_id: paymentId,
      status: 'open',
      mode: this.opts.notLive ? 'test' : 'live',
      amount: { currency: intent.currency, value: (intent.amount_minor / 100).toFixed(2) },
      metadata: {
        g_intent_id: intent.intent_id,
        g_intent_sha256: intent.intent_sha256,
        g_destination_binding_sha256: sha256(intent.destination_binding),
      },
    };
    // Model a crash: the provider effect lands, then the call fails ambiguously.
    if (this.opts.recordThenThrowAmbiguous) {
      this._store.set(paymentId, record);
      this.lastAmbiguousPaymentId = paymentId;
      throw new Error('socket hang up'); // no provider_http_status => ambiguous
    }
    if (this.opts.createThrowHttp) {
      const e = new Error('mollie_create_payment_failed');
      e.provider_http_status = 422;
      throw e;
    }
    if (this.opts.createThrowAmbiguous) {
      throw new Error('etimedout');
    }
    if (this.opts.createNoId) {
      return { provider: 'mollie-live', provider_http_status: 201, status: 'open' };
    }
    this._store.set(paymentId, record);
    return {
      provider: 'mollie-live',
      environment: 'LIVE',
      provider_http_status: 201,
      payment_id: paymentId,
      status: 'open',
      checkout_url: `https://pay.test/${paymentId}`,
      mode: record.mode,
      idempotent_replayed: false,
    };
  }

  _ambiguousKey(idk) {
    return `ambiguous:${sha256(String(idk))}`;
  }

  async getPayment(paymentId) {
    this.getCount += 1;
    if (this.opts.readbackThrow) {
      const e = new Error('mollie_payment_readback_failed');
      e.provider_http_status = 503;
      throw e;
    }
    let record = this._store.get(paymentId);
    // reconcile-by-idempotency path: the fake was asked with a synthetic id
    if (!record && this.opts.reconcileByAmbiguousKey) {
      record = this._store.get(this.opts.reconcileByAmbiguousKey);
    }
    if (!record) {
      const e = new Error('mollie_payment_readback_failed');
      e.provider_http_status = 404;
      throw e;
    }
    const out = {
      provider: 'mollie-live',
      payment_id: record.payment_id,
      status: record.status,
      mode: record.mode,
      amount: record.amount,
      metadata: record.metadata,
      provider_http_status: 200,
    };
    if (this.opts.readbackMismatchAmount) out.amount = { currency: 'EUR', value: '999.99' };
    if (this.opts.readbackMismatchCurrency) out.amount = { currency: 'USD', value: out.amount.value };
    if (this.opts.readbackMismatchId) out.payment_id = 'tr_totally_different';
    if (this.opts.readbackNoMetadata) out.metadata = null;
    if (this.opts.readbackNotLive) out.mode = 'test';
    return out;
  }
}

function ctxFor(dir, adapter, env, over = {}) {
  return {
    env,
    stateDir: dir,
    registry: buildMollieRegistry({ adapter, env }),
    policy: buildMolliePolicy({ actor: over.actor || 'operator:test', maxAmountMinor: over.maxAmountMinor || 100000 }),
    allowExternalEffects: over.allowExternalEffects === undefined ? true : over.allowExternalEffects,
    now: Date.now(),
  };
}

function buildAuthorizedRequest({ intent, env, actor = 'operator:test', expectedSequence = 1, idempotencyKey }) {
  const key = idempotencyKey || `idem-${crypto.randomUUID()}`;
  const request = buildMollieRequest({
    actor,
    requestId: `req-${crypto.randomUUID()}`,
    intent,
    idempotencyKey: key,
    expectedSequence,
  });
  request.authorization_token = createAuthorization(
    {
      requestCanonicalSha256: mollieBindingSha256(request),
      idempotencyKey: key,
      actor,
      capability: request.requested_capability,
      operation: request.operation,
      now: Date.now(),
    },
    env,
  );
  return { request, key };
}

// --------------------------------------------------------------------------
test('legacy live CLI routes through the spine: valid execution reaches VERIFIED_SUCCESS L4', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter();
  const intent = makeIntent();
  const { request } = buildAuthorizedRequest({ intent, env });

  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assertResult(r);
  assert.equal(r.state, RESULT_STATE.VERIFIED_SUCCESS);
  assert.equal(r.verification_method, VERIFICATION_METHOD.AUTHENTICATED_PROVIDER_READBACK);
  assert.equal(r.assurance_level_achieved, ASSURANCE.L4);
  assert.equal(r.provider, 'gbank.mollie.payment');
  assert.ok(r.provider_request_id.startsWith('tr_'));
  assert.equal(adapter.createCount, 1);
});

test('GBankLiveCore cannot be used to bypass the spine (retired)', () => {
  assert.equal(GBankLiveCore.retired, true);
  assert.throws(() => new GBankLiveCore({}), /retired/);
});

test('CI bypass detector catches forbidden imports/calls and passes clean code', () => {
  const selfTest = spawnSync(process.execPath, [path.join(REPO_ROOT, 'scripts', 'ci', 'check-spine-bypass.js'), '--self-test'], { encoding: 'utf8' });
  assert.equal(selfTest.status, 0, selfTest.stderr || selfTest.stdout);
  const fullScan = spawnSync(process.execPath, [path.join(REPO_ROOT, 'scripts', 'ci', 'check-spine-bypass.js')], { encoding: 'utf8' });
  assert.equal(fullScan.status, 0, fullScan.stderr || fullScan.stdout);
});

test('raw MollieLiveAdapter refuses a live mutation without a live key', async () => {
  const adapter = new MollieLiveAdapter({ apiKey: '' });
  await assert.rejects(() => adapter.createPayment({ intent: makeIntent(), idempotencyKey: 'x' }), /mollie_live_api_key_required/);
});

test('authorization failure causes zero provider calls', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter();
  const { request } = buildAuthorizedRequest({ intent: makeIntent(), env });
  request.authorization_token = 'bogus.token';
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.DENIED_AUTHORIZATION);
  assert.equal(adapter.createCount, 0);
  assert.equal(adapter.getCount, 0);
  assertResult(r);
});

test('policy failure causes zero provider calls', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter();
  const intent = makeIntent({ amount_minor: 5_000_00 }); // exceeds cap below
  const { request } = buildAuthorizedRequest({ intent, env });
  const ctx = ctxFor(dir, adapter, env, { maxAmountMinor: 100_00 });
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.DENIED_POLICY);
  assert.equal(adapter.createCount, 0);
  assertResult(r);
});

test('duplicate idempotency key => exactly one external effect', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter();
  const { request } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const ctx = ctxFor(dir, adapter, env);
  const r1 = await executeVerified(request, ctx);
  const r2 = await executeVerified(request, ctx);
  assert.equal(r1.state, RESULT_STATE.VERIFIED_SUCCESS);
  assert.equal(r2.state, RESULT_STATE.VERIFIED_SUCCESS);
  assert.equal(r2.replayed, true);
  assert.equal(adapter.createCount, 1);
});

test('concurrent duplicate execution => one external effect', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter();
  const { request } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const ctx = ctxFor(dir, adapter, env);
  const results = await Promise.all([
    executeVerified(request, ctx),
    executeVerified(request, ctx),
    executeVerified(request, ctx),
  ]);
  const fresh = results.filter((r) => r.state === RESULT_STATE.VERIFIED_SUCCESS && !r.replayed);
  assert.equal(fresh.length, 1);
  assert.equal(adapter.createCount, 1);
});

test('provider success + bad readback (id mismatch) != VERIFIED_SUCCESS', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter({ readbackMismatchId: true });
  const { request } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.READBACK_MISMATCH);
  assertResult(r);
});

test('readback with amount mismatch rejected', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter({ readbackMismatchAmount: true });
  const { request } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.READBACK_MISMATCH);
});

test('readback with currency mismatch rejected', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter({ readbackMismatchCurrency: true });
  const { request } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.READBACK_MISMATCH);
});

test('readback of a non-live payment rejected', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter({ readbackNotLive: true });
  const { request } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.READBACK_MISMATCH);
});

test('insufficient binding (no provider metadata) caps assurance at L3 / PROVIDER_RECEIPT_ONLY', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter({ readbackNoMetadata: true });
  const { request } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.VERIFIED_SUCCESS);
  assert.equal(r.assurance_level_achieved, ASSURANCE.L3);
  assert.equal(r.verification_method, VERIFICATION_METHOD.PROVIDER_RECEIPT_ONLY);
  assertResult(r);
});

test('valid strongly-bound provider readback reaches L4', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter();
  const { request } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.assurance_level_achieved, ASSURANCE.L4);
});

test('provider definite failure => PROVIDER_FAILURE, FAILED_FINAL, retry safe', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter({ createThrowHttp: true });
  const { request, key } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const ctx = ctxFor(dir, adapter, env);
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.PROVIDER_FAILURE);
  const truth = getExecutionTruth(key, { stateDir: dir });
  assert.equal(truth.record_state, 'FAILED_FINAL');
  assert.equal(truth.canonical_success, false);
  assert.equal(truth.retry_safe, true);
});

test('crash after external effect, before commit => no duplicate; reconcile confirms, recovers', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter({ recordThenThrowAmbiguous: true });
  const { request, key } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const ctx = ctxFor(dir, adapter, env);

  const r1 = await executeVerified(request, ctx);
  assert.equal(r1.state, RESULT_STATE.EXECUTION_UNVERIFIED);
  assert.equal(adapter.createCount, 1);

  // A blind retry must NOT re-execute.
  const r2 = await executeVerified(request, ctx);
  assert.equal(r2.state, RESULT_STATE.REPLAY_REJECTED);
  assert.equal(adapter.createCount, 1);

  const healthyAdapter = new FakeMollieAdapter({});
  healthyAdapter._store = adapter._store; // recovered process sees provider state

  // Without the Mollie payment id, reconcile cannot prove presence/absence and
  // must NOT permit a retry.
  const recNoId = await reconcile(
    { idempotency_key: key },
    { env, stateDir: dir, registry: buildMollieRegistry({ adapter: healthyAdapter, env }), capability: 'gbank.mollie.payment' },
  );
  assert.equal(recNoId.reconciled, false);
  assert.equal(recNoId.state, 'MANUAL_REQUIRED');

  // With the operator-supplied Mollie payment id, reconcile reads it back and
  // recovers the original execution — no new payment.
  const rec = await reconcile(
    { idempotency_key: key, provider_request_id: adapter.lastAmbiguousPaymentId },
    { env, stateDir: dir, registry: buildMollieRegistry({ adapter: healthyAdapter, env }), capability: 'gbank.mollie.payment' },
  );
  assert.equal(rec.state, 'EFFECT_CONFIRMED');
  assert.equal(healthyAdapter.createCount, 0, 'reconcile must not create a payment');
});

test('crash before provider call => STILL_UNCERTAIN without a payment id (no blind retry)', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  // ambiguous failure with nothing recorded provider-side
  const adapter = new FakeMollieAdapter({ createThrowAmbiguous: true });
  const { request, key } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const ctx = ctxFor(dir, adapter, env);
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.EXECUTION_UNVERIFIED);

  const rec = await reconcile(
    { idempotency_key: key },
    { env, stateDir: dir, registry: buildMollieRegistry({ adapter: new FakeMollieAdapter(), env }), capability: 'gbank.mollie.payment' },
  );
  // no provider_request_id, provider has nothing => cannot prove absence
  assert.ok(['STILL_UNCERTAIN', 'MANUAL_REQUIRED'].includes(rec.state), rec.state);
  assert.equal(rec.reconciled, false);
});

test('reconcile EFFECT_ABSENT is only reached when the provider definitively lacks the effect', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter({ createThrowAmbiguous: true });
  const { request, key } = buildAuthorizedRequest({ intent: makeIntent(), env });
  await executeVerified(request, ctxFor(dir, adapter, env));

  // A connector whose readback returns a definitive NOT_FOUND.
  const absentConnector = {
    name: 'gbank.mollie.payment',
    assurance_ceiling: 'L4',
    supportsReadback: true,
    async discover() { return { ok: true, observed_assurance: 'L2' }; },
    async captureState() { return 'S'; },
    async execute() { throw new Error('unused'); },
    async readback() { return { verified: false, observed_status: 'NOT_FOUND', external: true }; },
  };
  const { CapabilityRegistry } = require('../g-verified-execution-spine');
  const reg = new CapabilityRegistry();
  reg.register(absentConnector);
  const rec = await reconcile({ idempotency_key: key }, { env, stateDir: dir, registry: reg, capability: 'gbank.mollie.payment' });
  assert.equal(rec.state, 'EFFECT_ABSENT');
});

test('audit failure prevents canonical success', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter();

  // First a good execution to create the audit chain.
  const good = buildAuthorizedRequest({ intent: makeIntent(), env });
  await executeVerified(good.request, ctxFor(dir, adapter, env));

  // Corrupt the audit ledger, then a fresh execution must fail closed.
  const auditPath = path.join(dir, 'audit.jsonl');
  const rows = fs.readFileSync(auditPath, 'utf8').split('\n').filter(Boolean);
  const first = JSON.parse(rows[0]);
  first.actor = 'tampered';
  rows[0] = JSON.stringify(first);
  fs.writeFileSync(auditPath, rows.join('\n') + '\n');

  const next = buildAuthorizedRequest({ intent: makeIntent(), env, expectedSequence: 2 });
  const r = await executeVerified(next.request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.INTERNAL_FAIL_CLOSED);
  assert.equal(r.stage_reached, 'AUDIT');
  assert.equal(adapter.createCount, 1, 'no provider call once audit is known-broken');
});

test('sequence + idempotency durability survive a simulated crash (fsynced files persist)', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter();
  const { request, key } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.VERIFIED_SUCCESS);

  // "Crash": drop all in-memory state, re-open the stores from disk only.
  const idem = new IdempotencyStore(path.join(dir, 'idempotency'));
  const rec = idem.read(key);
  assert.equal(rec.state, 'SUCCEEDED');
  assert.equal(rec.result.state, 'VERIFIED_SUCCESS');

  const { SequenceStore } = require('../g-verified-execution-spine');
  const seq = new SequenceStore(path.join(dir, 'sequence'));
  assert.equal(seq.current('operator:test::gbank.mollie.payment'), 1);
  // no temp files left behind
  const seqFiles = fs.readdirSync(path.join(dir, 'sequence'));
  assert.equal(seqFiles.some((f) => f.endsWith('.tmp')), false);
});

test('secret redaction: intent metadata secrets never reach result/ledger/idempotency', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter();
  const intent = makeIntent({
    metadata: { order: 'ORD-9', access_token: 'live_deadbeefdeadbeefdeadbeef0001', client_secret: 'shh-very-secret' },
  });
  const { request, key } = buildAuthorizedRequest({ intent, env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.VERIFIED_SUCCESS);

  const haystacks = [
    JSON.stringify(r),
    fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8'),
    JSON.stringify(new IdempotencyStore(path.join(dir, 'idempotency')).read(key)),
  ];
  for (const h of haystacks) {
    assert.equal(h.includes('shh-very-secret'), false);
    assert.equal(h.includes('live_deadbeefdeadbeefdeadbeef0001'), false);
  }
  assert.equal(new ReceiptLedger(path.join(dir, 'audit.jsonl')).verify().valid, true);
});

test('execution truth: single authoritative answer for a verified payment', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter();
  const { request, key } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.VERIFIED_SUCCESS);

  const truth = getExecutionTruth(key, { stateDir: dir });
  assert.equal(truth.authorized, true);
  assert.equal(truth.execution_attempted, true);
  assert.equal(truth.provider_accepted, true);
  assert.equal(truth.externally_verified, true);
  assert.equal(truth.canonical_success, true);
  assert.equal(truth.audit_chain_valid, true);
  assert.equal(truth.retry_safe, false);
});

test('discover() gate: allowExternalEffects=false => NO_VERIFIED_PATH, zero provider mutation', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeMollieAdapter();
  const { request } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const ctx = ctxFor(dir, adapter, env, { allowExternalEffects: false });
  const r = await executeVerified(request, ctx);
  assert.equal(r.state, RESULT_STATE.NO_VERIFIED_PATH);
  assert.equal(adapter.createCount, 0);
});

test('env not live (G_BANK_ENABLE_LIVE unset) => NO_VERIFIED_PATH', async () => {
  const dir = tmpDir();
  const env = { G_SPINE_AUTHORIZATION_SECRET: 'k'.repeat(48) }; // missing live flags
  const adapter = new FakeMollieAdapter();
  const { request } = buildAuthorizedRequest({ intent: makeIntent(), env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.NO_VERIFIED_PATH);
  assert.equal(adapter.createCount, 0);
});
