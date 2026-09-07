const assert = require('node:assert/strict');
const crypto = require('node:crypto');

process.env.TRUELAYER_ENV = 'sandbox';
process.env.G_BANK_MAX_PAYMENT_EUR = '100';
process.env.G_BANK_ENABLE_LIVE = 'false';

const router = require('../routes/openbanking');
const {
  isValidIban,
  approvalMessage,
  assertPaymentInput,
  assertLiveApproval
} = router._test;

function mustThrow(fn, pattern) {
  let error;
  try {
    fn();
  } catch (err) {
    error = err;
  }
  assert.ok(error, 'expected function to throw');
  if (pattern) assert.match(String(error.message), pattern);
}

assert.equal(isValidIban('NL91 ABNA 0417 1643 00'), true);
assert.equal(isValidIban('NL91 ABNA 0417 1643 01'), false);
assert.equal(isValidIban('not-an-iban'), false);

const parsed = assertPaymentInput({
  amount_eur: '12.34',
  beneficiary: {
    name: 'Test Merchant',
    iban: 'NL91ABNA0417164300',
    reference: 'TEST-123'
  },
  user: {
    name: 'Test User',
    email: 'test@example.invalid',
    phone: '+31600000000',
    date_of_birth: '1990-01-01',
    address: {
      address_line1: 'Teststraat 1',
      city: 'Amsterdam',
      zip: '1000AA',
      country_code: 'NL'
    }
  }
});

assert.equal(parsed.amountInMinor, 1234);
assert.equal(parsed.amountEur, 12.34);
assert.equal(parsed.beneficiary.iban, 'NL91ABNA0417164300');

mustThrow(() => assertPaymentInput({
  ...{
    amount_eur: '100.01',
    beneficiary: {
      name: 'Test Merchant',
      iban: 'NL91ABNA0417164300',
      reference: 'TEST-123'
    },
    user: {
      name: 'Test User',
      email: 'test@example.invalid',
      phone: '+31600000000',
      date_of_birth: '1990-01-01',
      address: {
        address_line1: 'Teststraat 1',
        city: 'Amsterdam',
        zip: '1000AA',
        country_code: 'NL'
      }
    }
  }
}), /exceeds/);

mustThrow(() => assertPaymentInput({
  amount_eur: '12.34',
  beneficiary: {
    name: 'Test Merchant',
    iban: 'NL91ABNA0417164301',
    reference: 'TEST-123'
  },
  user: {
    name: 'Test User',
    email: 'test@example.invalid',
    phone: '+31600000000',
    date_of_birth: '1990-01-01',
    address: {
      address_line1: 'Teststraat 1',
      city: 'Amsterdam',
      zip: '1000AA',
      country_code: 'NL'
    }
  }
}), /checksum/);

// Live approval is bound to exact intent parameters.
process.env.TRUELAYER_ENV = 'live';
process.env.G_BANK_ENABLE_LIVE = 'true';
process.env.G_BANK_MAX_PAYMENT_EUR = '100';
process.env.G_BANK_APPROVAL_SECRET = 'unit-test-secret';
process.env.G_BANK_ALLOWED_BENEFICIARY_IBANS = 'NL91ABNA0417164300';
process.env.TRUELAYER_CLIENT_ID = 'test-client';
process.env.TRUELAYER_CLIENT_SECRET = 'test-secret';
process.env.TRUELAYER_SIGNING_KID = 'test-kid';
process.env.TRUELAYER_PRIVATE_KEY_PEM = 'test-key';
process.env.TRUELAYER_RETURN_URI = 'https://example.invalid/return';

const intent = {
  idempotencyKey: '11111111-1111-4111-8111-111111111111',
  amountInMinor: 1234,
  iban: 'NL91ABNA0417164300',
  reference: 'TEST-123'
};

const approval = crypto
  .createHmac('sha256', process.env.G_BANK_APPROVAL_SECRET)
  .update(approvalMessage(intent))
  .digest('hex');

assert.doesNotThrow(() => assertLiveApproval({
  ...intent,
  approvalHeader: approval
}));

mustThrow(() => assertLiveApproval({
  ...intent,
  amountInMinor: 1235,
  approvalHeader: approval
}), /did not match/);

mustThrow(() => assertLiveApproval({
  ...intent,
  iban: 'NL02RABO0123456789',
  approvalHeader: approval
}), /allowlist/);

console.log('Open Banking policy tests: PASS');
