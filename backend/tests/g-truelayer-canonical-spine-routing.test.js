'use strict';

// TRUELAYER-CANONICAL-SPINE-ROUTING-P0
//
// Every live TrueLayer payment creation goes through executeVerified() +
// TrueLayerSpineConnector. Driven here with an injected fake adapter (no
// network, no value movement).

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const { sha256 } = require('../g-bank-live-v1/canonical');
const { TrueLayerLiveAdapter } = require('../g-bank-live-v1/providers/truelayer-live');
const {
  executeVerified,
  reconcile,
  createAuthorization,
  assertResult,
  RESULT_STATE,
  ASSURANCE,
  VERIFICATION_METHOD,
  getExecutionTruth,
  CapabilityRegistry,
  buildTrueLayerRegistry,
  buildTrueLayerPolicy,
  buildTrueLayerRequest,
  truelayerBindingSha256,
} = require('../g-verified-execution-spine');
const { IdempotencyStore } = require('../g-bank-live-v1/idempotency-store');
const { ReceiptLedger } = require('../g-bank-live-v1/receipt-ledger');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SECRET = 'k'.repeat(48);

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'g-tl-routing-'));
}

function liveEnv(extra = {}) {
  return {
    G_BANK_ENABLE_LIVE: 'true',
    G_BANK_EXTERNAL_ACTIONS_ENABLED: 'true',
    G_BANK_SIMULATED_LIVE_SUCCESS: 'false',
    G_SPINE_AUTHORIZATION_SECRET: SECRET,
    TRUELAYER_ENV: 'sandbox',
    ...extra,
  };
}

function beneficiary() {
  return { iban: 'NL91ABNA0417164300', name: 'Jane Beneficiary', reference: 'INV-4472' };
}
function user() {
  return {
    name: 'Payer Person',
    email: 'payer@example.test',
    phone: '+31600000000',
    date_of_birth: '1990-01-01',
    address: { address_line1: 'Teststraat 1', city: 'Amsterdam', zip: '1011AA', country_code: 'nl' },
  };
}

class FakeTrueLayerAdapter {
  constructor(opts = {}) {
    this.opts = opts;
    this.tokenCount = 0;
    this.preflightCount = 0;
    this.createCount = 0;
    this.getCount = 0;
    this._store = new Map();
    this.env = opts.env || { TRUELAYER_ENV: 'sandbox' };
  }
  _environment() {
    return String(this.env.TRUELAYER_ENV || 'sandbox').toLowerCase() === 'live' ? 'LIVE' : 'SANDBOX';
  }
  async preflight() {
    this.preflightCount += 1;
    if (this.opts.preflightUnauthenticated) {
      const e = new Error('truelayer_token_request_failed');
      e.provider_http_status = 401;
      throw e;
    }
    return {
      provider: 'truelayer-live',
      environment: this._environment(),
      authenticated: true,
      signature_accepted: this.opts.signatureRejected ? false : true,
      provider_http_status: this.opts.signatureRejected ? 401 : 204,
      payment_endpoint_called: false,
      value_moved: false,
    };
  }
  async createPayment({ body, idempotencyKey }) {
    this.createCount += 1;
    if (this.opts.createThrowHttp) {
      const e = new Error('truelayer_create_payment_failed');
      e.provider_http_status = 422;
      throw e;
    }
    if (this.opts.createThrowAmbiguous) throw new Error('truelayer_timeout'); // no http status
    if (this.opts.createNoId) return { provider: 'truelayer-live', provider_http_status: 201, payment_id: null };
    const paymentId = (crypto.randomUUID());
    const ben = body.payment_method.beneficiary;
    const record = {
      payment_id: paymentId,
      status: 'authorization_required',
      environment: this._environment(),
      amount_in_minor: body.amount_in_minor,
      currency: body.currency,
      beneficiary_iban: ben.account_identifier.iban,
      beneficiary_reference: ben.reference,
      metadata: body.metadata,
      created_at: new Date().toISOString(),
    };
    if (this.opts.recordThenThrowAmbiguous) {
      this._store.set(paymentId, record);
      this.lastAmbiguousPaymentId = paymentId;
      throw new Error('truelayer_socket_hang_up');
    }
    this._store.set(paymentId, record);
    return {
      provider: 'truelayer-live',
      environment: this._environment(),
      provider_http_status: 201,
      payment_id: paymentId,
      status: 'authorization_required',
      authorization_url: `https://pay.truelayer-sandbox.com/${paymentId}`,
      idempotent_replayed: false,
    };
  }
  async getPayment(paymentId) {
    this.getCount += 1;
    if (this.opts.readbackThrow) {
      const e = new Error('truelayer_payment_readback_failed');
      e.provider_http_status = 503;
      throw e;
    }
    const rec = this._store.get(paymentId);
    if (!rec) {
      const e = new Error('truelayer_payment_readback_failed');
      e.provider_http_status = 404;
      throw e;
    }
    const out = { provider: 'truelayer-live', provider_http_status: 200, ...rec };
    if (this.opts.readbackMismatchId) out.payment_id = 'different-id-0000';
    if (this.opts.readbackMismatchAmount) out.amount_in_minor = 999999;
    if (this.opts.readbackMismatchCurrency) out.currency = 'USD';
    if (this.opts.readbackMismatchIban) out.beneficiary_iban = 'NL02RABO0123456789';
    if (this.opts.readbackMismatchReference) out.beneficiary_reference = 'TAMPERED-REF';
    if (this.opts.readbackWrongEnv) out.environment = 'LIVE';
    if (this.opts.readbackNoMetadata) out.metadata = null;
    return out;
  }
}

function ctxFor(dir, adapter, env, over = {}) {
  return {
    env,
    stateDir: dir,
    registry: buildTrueLayerRegistry({ adapter, env }),
    policy: buildTrueLayerPolicy({ actor: over.actor || 'operator:test', maxAmountMinor: over.maxAmountMinor || 1_000_00 }),
    allowExternalEffects: over.allowExternalEffects === undefined ? true : over.allowExternalEffects,
    now: Date.now(),
  };
}

function buildAuthorized({ env, actor = 'operator:test', amountMinor = 4472, expectedSequence = 1, idempotencyKey, environment = 'sandbox' }) {
  const key = idempotencyKey || `idem-${crypto.randomUUID()}`;
  const request = buildTrueLayerRequest({
    actor,
    requestId: `tlreq-${crypto.randomUUID()}`,
    idempotencyKey: key,
    expectedSequence,
    environment,
    amountMinor,
    currency: 'EUR',
    beneficiary: beneficiary(),
    user: user(),
    returnUri: 'https://g-bank.test/api/open-banking/return',
  });
  request.authorization_token = createAuthorization(
    {
      requestCanonicalSha256: truelayerBindingSha256(request),
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

// -------------------------------------------------------------------------
test('TrueLayer route path: valid execution reaches VERIFIED_SUCCESS L4', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env });
  const { request } = buildAuthorized({ env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assertResult(r);
  assert.equal(r.state, RESULT_STATE.VERIFIED_SUCCESS);
  assert.equal(r.provider, 'gbank.truelayer.payment');
  assert.equal(r.verification_method, VERIFICATION_METHOD.AUTHENTICATED_PROVIDER_READBACK);
  assert.equal(r.assurance_level_achieved, ASSURANCE.L4);
  assert.equal(adapter.createCount, 1);
});

test('escape hatch G_BANK_ALLOW_UNSPINED_TRUELAYER no longer exists anywhere in runtime code', () => {
  const grep = spawnSync(
    'grep',
    ['-rIn', '--include=*.js', '--include=*.yml', '--include=*.json', '--exclude=*.test.js',
      'G_BANK_ALLOW_UNSPINED_TRUELAYER', 'backend', 'scripts', '.github'],
    { cwd: REPO_ROOT, encoding: 'utf8' },
  );
  // grep exit 1 == no matches
  assert.equal(grep.status, 1, `escape hatch still referenced:\n${grep.stdout}`);
});

test('openbanking.js /create-payment contains no direct provider payment POST', () => {
  const src = fs.readFileSync(path.join(REPO_ROOT, 'backend/routes/openbanking.js'), 'utf8');
  assert.equal(/axios\s*\.\s*post\s*\([^)]*\/v\d\/payments/.test(src), false);
  assert.equal(/\.post\s*\(\s*[`'"][^`'"]*\/v\d\/payments[`'"]/.test(src), false);
  assert.ok(src.includes("require('../g-verified-execution-spine/spine')"));
  assert.ok(src.includes('executeVerified('));
});

test('CI guard catches direct TrueLayer mutation bypass', () => {
  const st = spawnSync(process.execPath, [path.join(REPO_ROOT, 'scripts/ci/check-spine-bypass.js'), '--self-test'], { encoding: 'utf8' });
  assert.equal(st.status, 0, st.stderr || st.stdout);
  const scan = spawnSync(process.execPath, [path.join(REPO_ROOT, 'scripts/ci/check-spine-bypass.js')], { encoding: 'utf8' });
  assert.equal(scan.status, 0, scan.stderr || scan.stdout);
});

test('raw TrueLayerLiveAdapter refuses a live mutation without configuration', async () => {
  const a = new TrueLayerLiveAdapter({ env: {} });
  await assert.rejects(() => a.createPayment({ body: {}, idempotencyKey: 'x' }), /truelayer_client_credentials_missing/);
});

test('policy denial (amount over cap) => zero provider mutation calls', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env });
  const { request } = buildAuthorized({ env, amountMinor: 500_000 });
  const r = await executeVerified(request, ctxFor(dir, adapter, env, { maxAmountMinor: 100_00 }));
  assert.equal(r.state, RESULT_STATE.DENIED_POLICY);
  assert.equal(adapter.createCount, 0);
  assertResult(r);
});

test('authorization denial => zero provider mutation calls', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env });
  const { request } = buildAuthorized({ env });
  request.authorization_token = 'not.a.valid.token';
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.DENIED_AUTHORIZATION);
  assert.equal(adapter.createCount, 0);
});

test('wrong request hash (mutated params after minting) => DENIED_AUTHORIZATION', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env });
  const { request } = buildAuthorized({ env });
  request.params.amount_minor = request.params.amount_minor + 1;
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.DENIED_AUTHORIZATION);
  assert.equal(adapter.createCount, 0);
});

test('live disabled (missing env flags) => NO_VERIFIED_PATH, no mutation', async () => {
  const dir = tmpDir();
  const env = { G_SPINE_AUTHORIZATION_SECRET: SECRET, TRUELAYER_ENV: 'sandbox' };
  const adapter = new FakeTrueLayerAdapter({ env });
  const { request } = buildAuthorized({ env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.NO_VERIFIED_PATH);
  assert.equal(adapter.createCount, 0);
});

test('external effects disabled => NO_VERIFIED_PATH, no mutation', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env });
  const { request } = buildAuthorized({ env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env, { allowExternalEffects: false }));
  assert.equal(r.state, RESULT_STATE.NO_VERIFIED_PATH);
  assert.equal(adapter.createCount, 0);
});

test('preflight signature rejected => NO_VERIFIED_PATH', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env, signatureRejected: true });
  const { request } = buildAuthorized({ env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.NO_VERIFIED_PATH);
  assert.equal(adapter.createCount, 0);
});

test('duplicate idempotency key => one provider effect', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env });
  const { request } = buildAuthorized({ env });
  const ctx = ctxFor(dir, adapter, env);
  const r1 = await executeVerified(request, ctx);
  const r2 = await executeVerified(request, ctx);
  assert.equal(r1.state, RESULT_STATE.VERIFIED_SUCCESS);
  assert.equal(r2.state, RESULT_STATE.VERIFIED_SUCCESS);
  assert.equal(r2.replayed, true);
  assert.equal(adapter.createCount, 1);
});

test('concurrent duplicate calls => one provider effect', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env });
  const { request } = buildAuthorized({ env });
  const ctx = ctxFor(dir, adapter, env);
  const rs = await Promise.all([executeVerified(request, ctx), executeVerified(request, ctx), executeVerified(request, ctx)]);
  assert.equal(rs.filter((r) => r.state === RESULT_STATE.VERIFIED_SUCCESS && !r.replayed).length, 1);
  assert.equal(adapter.createCount, 1);
});

test('provider timeout before acceptance => EXECUTION_UNVERIFIED + quarantine; blind retry rejected', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env, createThrowAmbiguous: true });
  const { request, key } = buildAuthorized({ env });
  const ctx = ctxFor(dir, adapter, env);
  const r1 = await executeVerified(request, ctx);
  assert.equal(r1.state, RESULT_STATE.EXECUTION_UNVERIFIED);
  const r2 = await executeVerified(request, ctx);
  assert.equal(r2.state, RESULT_STATE.REPLAY_REJECTED);
  assert.equal(getExecutionTruth(key, { stateDir: dir }).retry_safe, false);
});

test('provider definite failure => PROVIDER_FAILURE, FAILED_FINAL, retry safe', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env, createThrowHttp: true });
  const { request, key } = buildAuthorized({ env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.PROVIDER_FAILURE);
  const truth = getExecutionTruth(key, { stateDir: dir });
  assert.equal(truth.record_state, 'FAILED_FINAL');
  assert.equal(truth.retry_safe, true);
});

test('provider accepts + response lost => quarantine; reconcile with payment id confirms, no reissue', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env, recordThenThrowAmbiguous: true });
  const { request, key } = buildAuthorized({ env });
  const r1 = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r1.state, RESULT_STATE.EXECUTION_UNVERIFIED);
  assert.equal(adapter.createCount, 1);

  const healthy = new FakeTrueLayerAdapter({ env });
  healthy._store = adapter._store;

  const noId = await reconcile(
    { idempotency_key: key },
    { env, stateDir: dir, registry: buildTrueLayerRegistry({ adapter: healthy, env }), capability: 'gbank.truelayer.payment' },
  );
  assert.equal(noId.reconciled, false);
  assert.equal(noId.state, 'MANUAL_REQUIRED');

  const rec = await reconcile(
    { idempotency_key: key, provider_request_id: adapter.lastAmbiguousPaymentId },
    { env, stateDir: dir, registry: buildTrueLayerRegistry({ adapter: healthy, env }), capability: 'gbank.truelayer.payment' },
  );
  assert.equal(rec.state, 'EFFECT_CONFIRMED');
  assert.equal(healthy.createCount, 0);
});

test('reconcile when provider definitely has no payment => EFFECT_ABSENT', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env, createThrowAmbiguous: true });
  const { request, key } = buildAuthorized({ env });
  await executeVerified(request, ctxFor(dir, adapter, env));

  const absentConnector = {
    name: 'gbank.truelayer.payment',
    assurance_ceiling: 'L4',
    supportsReadback: true,
    async discover() { return { ok: true, observed_assurance: 'L2' }; },
    async captureState() { return 'S'; },
    async execute() { throw new Error('unused'); },
    async readback() { return { verified: false, observed_status: 'NOT_FOUND', external: true }; },
  };
  const reg = new CapabilityRegistry();
  reg.register(absentConnector);
  const rec = await reconcile({ idempotency_key: key }, { env, stateDir: dir, registry: reg, capability: 'gbank.truelayer.payment' });
  assert.equal(rec.state, 'EFFECT_ABSENT');
});

test('provider receipt only (no metadata binding) => capped at L3 / PROVIDER_RECEIPT_ONLY', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env, readbackNoMetadata: true });
  const { request } = buildAuthorized({ env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.VERIFIED_SUCCESS);
  assert.equal(r.assurance_level_achieved, ASSURANCE.L3);
  assert.equal(r.verification_method, VERIFICATION_METHOD.PROVIDER_RECEIPT_ONLY);
});

for (const [label, opt] of [
  ['payment-id', { readbackMismatchId: true }],
  ['amount', { readbackMismatchAmount: true }],
  ['currency', { readbackMismatchCurrency: true }],
  ['beneficiary iban', { readbackMismatchIban: true }],
  ['beneficiary reference', { readbackMismatchReference: true }],
  ['environment', { readbackWrongEnv: true }],
]) {
  test(`readback ${label} mismatch => READBACK_MISMATCH, not success`, async () => {
    const dir = tmpDir();
    const env = liveEnv();
    const adapter = new FakeTrueLayerAdapter({ env, ...opt });
    const { request } = buildAuthorized({ env });
    const r = await executeVerified(request, ctxFor(dir, adapter, env));
    assert.equal(r.state, RESULT_STATE.READBACK_MISMATCH);
    assert.notEqual(r.canonical_commit_status, 'COMMITTED');
    assertResult(r);
  });
}

test('LIVE environment: beneficiary not in allowlist => refused, no payment created', async () => {
  const dir = tmpDir();
  const env = liveEnv({ TRUELAYER_ENV: 'live', G_BANK_ALLOWED_BENEFICIARY_IBANS: 'NL02RABO0123456789' });
  const adapter = new FakeTrueLayerAdapter({ env });
  const { request } = buildAuthorized({ env, environment: 'live' });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.PROVIDER_FAILURE); // definite refusal, FAILED_FINAL, no effect
  assert.equal(adapter.createCount, 0);
});

test('secret + PII redaction: no beneficiary/user PII in result, ledger, idempotency record', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env });
  const { request, key } = buildAuthorized({ env });
  const r = await executeVerified(request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.VERIFIED_SUCCESS);
  const haystacks = [
    JSON.stringify(r),
    fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8'),
    JSON.stringify(new IdempotencyStore(path.join(dir, 'idempotency')).read(key)),
  ];
  for (const h of haystacks) {
    assert.equal(h.includes('NL91ABNA0417164300'), false, 'beneficiary IBAN leaked');
    assert.equal(h.includes('Jane Beneficiary'), false, 'beneficiary name leaked');
    assert.equal(h.includes('Payer Person'), false, 'payer name leaked');
    assert.equal(h.includes('payer@example.test'), false, 'email leaked');
    assert.equal(h.includes('Teststraat 1'), false, 'address leaked');
    assert.equal(h.includes('1990-01-01'), false, 'dob leaked');
  }
  assert.equal(new ReceiptLedger(path.join(dir, 'audit.jsonl')).verify().valid, true);
});

test('audit-chain corruption => next execution fails closed at AUDIT, no provider call', async () => {
  const dir = tmpDir();
  const env = liveEnv();
  const adapter = new FakeTrueLayerAdapter({ env });
  await executeVerified(buildAuthorized({ env }).request, ctxFor(dir, adapter, env));

  const auditPath = path.join(dir, 'audit.jsonl');
  const rows = fs.readFileSync(auditPath, 'utf8').split('\n').filter(Boolean);
  const first = JSON.parse(rows[0]);
  first.actor = 'tampered';
  rows[0] = JSON.stringify(first);
  fs.writeFileSync(auditPath, rows.join('\n') + '\n');

  const r = await executeVerified(buildAuthorized({ env, expectedSequence: 2 }).request, ctxFor(dir, adapter, env));
  assert.equal(r.state, RESULT_STATE.INTERNAL_FAIL_CLOSED);
  assert.equal(r.stage_reached, 'AUDIT');
  assert.equal(adapter.createCount, 1);
});

test('ambient env vars do not change security-test outcome (hermetic)', async () => {
  const dir = tmpDir();
  const prev = process.env.G_BANK_EXTERNAL_ACTIONS_ENABLED;
  process.env.G_BANK_EXTERNAL_ACTIONS_ENABLED = 'true'; // hostile ambient value
  try {
    const env = { G_SPINE_AUTHORIZATION_SECRET: SECRET, TRUELAYER_ENV: 'sandbox' }; // explicit env, no live flags
    const adapter = new FakeTrueLayerAdapter({ env });
    const { request } = buildAuthorized({ env });
    const r = await executeVerified(request, ctxFor(dir, adapter, env));
    assert.equal(r.state, RESULT_STATE.NO_VERIFIED_PATH);
    assert.equal(adapter.createCount, 0);
  } finally {
    if (prev === undefined) delete process.env.G_BANK_EXTERNAL_ACTIONS_ENABLED;
    else process.env.G_BANK_EXTERNAL_ACTIONS_ENABLED = prev;
  }
});

test('webhook receipt cannot forge canonical success: execution truth ignores webhooks', () => {
  // getExecutionTruth derives only from the spine idempotency record + audit
  // ledger. With no spine execution for a key, nothing a webhook writes can
  // make it canonical.
  const dir = tmpDir();
  const truth = getExecutionTruth('never-executed-key-00000000', { stateDir: dir });
  assert.equal(truth.canonical_success, false);
  assert.equal(truth.provider_accepted, false);
  assert.equal(truth.externally_verified, false);
});
