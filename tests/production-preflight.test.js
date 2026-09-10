const test = require('node:test');
const assert = require('node:assert/strict');

const {
  classifyMollieKey,
  validatePublicBaseUrl,
  validatePaymentStateBackend,
  runProductionPreflight,
} = require('../backend/utils/production-preflight');

test('Mollie key mode classification distinguishes live and test keys', () => {
  assert.equal(classifyMollieKey('live_example'), 'live');
  assert.equal(classifyMollieKey('test_example'), 'test');
  assert.equal(classifyMollieKey(''), 'missing');
  assert.equal(classifyMollieKey('other_example'), 'unknown');
});

test('public base URL requires non-local HTTPS', () => {
  assert.equal(validatePublicBaseUrl('http://example.com').ok, false);
  assert.equal(validatePublicBaseUrl('https://localhost:4000').ok, false);
  assert.equal(validatePublicBaseUrl('https://127.0.0.1').ok, false);
  assert.equal(validatePublicBaseUrl('https://pay.example.com').ok, true);
});

test('payment state backend defaults to local single-host mode', () => {
  const state = validatePaymentStateBackend({});
  assert.equal(state.ok, true);
  assert.equal(state.backend, 'local');
  assert.equal(state.status, 'local_single_host');
});

test('postgres payment state fails closed without connection URL', () => {
  const state = validatePaymentStateBackend(
    { GPAY_PAYMENT_STATE_BACKEND: 'postgres' },
    () => '/node_modules/pg/index.js'
  );
  assert.equal(state.ok, false);
  assert.equal(state.status, 'postgres_url_missing');
  assert.equal(state.driverAvailable, true);
});

test('postgres payment state fails closed when driver is unavailable', () => {
  const state = validatePaymentStateBackend(
    {
      GPAY_PAYMENT_STATE_BACKEND: 'postgres',
      GPAY_POSTGRES_URL: 'postgresql://gpay:secret@db.example.invalid:5432/gpay',
    },
    () => { throw new Error('module missing'); }
  );
  assert.equal(state.ok, false);
  assert.equal(state.status, 'postgres_driver_missing');
  assert.equal(state.postgresUrlPresent, true);
});

test('postgres payment state qualifies only with URL and installed driver', () => {
  const state = validatePaymentStateBackend(
    {
      GPAY_PAYMENT_STATE_BACKEND: 'postgres',
      GPAY_POSTGRES_URL: 'postgresql://gpay:secret@db.example.invalid:5432/gpay',
    },
    () => '/node_modules/pg/index.js'
  );
  assert.equal(state.ok, true);
  assert.equal(state.status, 'postgres_configured');
});

test('unsupported payment state backend fails closed', () => {
  const state = validatePaymentStateBackend({ GPAY_PAYMENT_STATE_BACKEND: 'redis' });
  assert.equal(state.ok, false);
  assert.equal(state.status, 'unsupported_backend');
});

test('preflight fails closed for missing configuration', () => {
  const result = runProductionPreflight({});
  assert.equal(result.readyForLivePaymentCreation, false);
  assert.equal(result.externalExecutionPerformed, false);
  assert.equal(result.livePaymentCreated, false);
  assert.equal(result.gcoinSettlementExecution, 'not_attempted');
});

test('test Mollie credentials never qualify as live-ready', () => {
  const result = runProductionPreflight({
    MOLLIE_API_KEY: 'test_example',
    GPAY_PUBLIC_BASE_URL: 'https://pay.example.com',
  });
  assert.equal(result.readyForLivePaymentCreation, false);
});

test('valid live-form local configuration can be classified ready without executing anything', () => {
  const result = runProductionPreflight({
    MOLLIE_API_KEY: 'live_example',
    GPAY_PUBLIC_BASE_URL: 'https://pay.example.com',
  });
  assert.equal(result.readyForLivePaymentCreation, true);
  assert.equal(result.externalExecutionPerformed, false);
  assert.equal(result.livePaymentCreated, false);
  assert.equal(result.gcoinSettlementExecution, 'not_attempted');

  const stateCheck = result.checks.find((check) => check.name === 'PAYMENT_STATE_BACKEND');
  assert.equal(stateCheck.status, 'local_single_host');

  const gcoinCheck = result.checks.find((check) => check.name === 'GCOIN_EXTERNAL_EXECUTION');
  assert.equal(gcoinCheck.status, 'disabled_intent_only');
  assert.equal(gcoinCheck.broadcast, false);
});

test('postgres-selected live preflight refuses readiness without database URL', () => {
  const result = runProductionPreflight({
    MOLLIE_API_KEY: 'live_example',
    GPAY_PUBLIC_BASE_URL: 'https://pay.example.com',
    GPAY_PAYMENT_STATE_BACKEND: 'postgres',
  }, { resolvePg: () => '/node_modules/pg/index.js' });
  assert.equal(result.readyForLivePaymentCreation, false);
  const stateCheck = result.checks.find((check) => check.name === 'PAYMENT_STATE_BACKEND');
  assert.equal(stateCheck.status, 'postgres_url_missing');
});
