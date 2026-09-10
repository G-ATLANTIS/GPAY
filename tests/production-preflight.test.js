const test = require('node:test');
const assert = require('node:assert/strict');

const {
  classifyMollieKey,
  validatePublicBaseUrl,
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

test('valid live-form configuration can be classified ready without executing anything', () => {
  const result = runProductionPreflight({
    MOLLIE_API_KEY: 'live_example',
    GPAY_PUBLIC_BASE_URL: 'https://pay.example.com',
  });
  assert.equal(result.readyForLivePaymentCreation, true);
  assert.equal(result.externalExecutionPerformed, false);
  assert.equal(result.livePaymentCreated, false);
  assert.equal(result.gcoinSettlementExecution, 'not_attempted');

  const gcoinCheck = result.checks.find((check) => check.name === 'GCOIN_EXTERNAL_EXECUTION');
  assert.equal(gcoinCheck.status, 'disabled_intent_only');
  assert.equal(gcoinCheck.broadcast, false);
});
