'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { AccountRegistry } = require('../g-bank-sovereign-v2/accounts');
const { SovereignLedger } = require('../g-bank-sovereign-v2/ledger');
const { assessSafeguarding } = require('../g-bank-sovereign-v2/safeguarding');
const { assessLiquidity } = require('../g-bank-sovereign-v2/liquidity');
const { auditSovereignInvariants } = require('../g-bank-sovereign-v2/invariant-auditor');

const H = c => c.repeat(64);

function setup() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-prudential-'));
  const accounts = new AccountRegistry(path.join(root, 'accounts.json'));
  const ledger = new SovereignLedger(path.join(root, 'ledger.jsonl'));
  const rows = [
    ['G:TREASURY:001', 'TREASURY', null, H('1')],
    ['G:CUSTOMER:001', 'CUSTOMER', 'NL91ABNA0417164300', H('2')],
    ['G:SAFEGUARDING:001', 'SAFEGUARDING', null, H('3')],
    ['G:SUSPENSE:OUTBOUND', 'SUSPENSE', null, H('4')],
    ['G:SETTLEMENT:OUTBOUND', 'SETTLEMENT', null, H('5')],
  ];
  for (const [account_id, type, iban, owner_binding_sha256] of rows) {
    accounts.register({ account_id, type, currency: 'EUR', iban, owner_binding_sha256 });
  }
  ledger.post({
    transaction_id: 'FUND-CUSTOMER-1',
    entries: [
      { account_id: 'G:TREASURY:001', side: 'DEBIT', amount_minor: 10000, currency: 'EUR' },
      { account_id: 'G:CUSTOMER:001', side: 'CREDIT', amount_minor: 10000, currency: 'EUR' },
    ],
  });
  ledger.post({
    transaction_id: 'FUND-SAFEGUARDING-1',
    entries: [
      { account_id: 'G:TREASURY:001', side: 'DEBIT', amount_minor: 12000, currency: 'EUR' },
      { account_id: 'G:SAFEGUARDING:001', side: 'CREDIT', amount_minor: 12000, currency: 'EUR' },
    ],
  });
  return { root, accounts, ledger };
}

(() => {
  const s = setup();
  const trial = s.ledger.trialBalance('EUR');
  assert.equal(trial.balanced, true);
  assert.equal(trial.total_minor, 0);
  assert.equal(trial.balances['G:CUSTOMER:001'], 10000);
  assert.equal(s.accounts.list({ type: 'CUSTOMER', currency: 'EUR', status: 'ACTIVE' }).length, 1);

  const safeguarding = assessSafeguarding({
    customer_liabilities_minor: 10000,
    safeguarded_assets_minor: 12000,
    pending_outbound_holds_minor: 500,
    required_buffer_minor: 1000,
    evidence_sha256: H('a'),
  });
  assert.equal(safeguarding.state, 'PASS');
  assert.equal(safeguarding.surplus_minor, 500);

  const liquidity = assessLiquidity({
    immediately_available_minor: 15000,
    pending_outbound_minor: 3000,
    stressed_outflow_minor: 5000,
    minimum_buffer_minor: 2000,
  });
  assert.equal(liquidity.state, 'PASS');
  assert.equal(liquidity.headroom_minor, 5000);

  const audit = auditSovereignInvariants({
    accounts: s.accounts,
    ledger: s.ledger,
    safeguardingAssessment: safeguarding,
    liquidityAssessment: liquidity,
  });
  assert.equal(audit.state, 'PASS');
  assert.deepEqual(audit.reasons, []);

  const underSafeguarded = assessSafeguarding({
    customer_liabilities_minor: 10000,
    safeguarded_assets_minor: 9000,
    pending_outbound_holds_minor: 500,
    required_buffer_minor: 1000,
    evidence_sha256: H('b'),
  });
  const blocked = auditSovereignInvariants({
    accounts: s.accounts,
    ledger: s.ledger,
    safeguardingAssessment: underSafeguarded,
    liquidityAssessment: liquidity,
  });
  assert.equal(blocked.state, 'BLOCK');
  assert.ok(blocked.reasons.includes('SAFEGUARDING_COVERAGE_BLOCKED'));

  const thinLiquidity = assessLiquidity({
    immediately_available_minor: 4000,
    pending_outbound_minor: 3000,
    stressed_outflow_minor: 2000,
    minimum_buffer_minor: 1000,
  });
  const liquidityBlocked = auditSovereignInvariants({
    accounts: s.accounts,
    ledger: s.ledger,
    safeguardingAssessment: safeguarding,
    liquidityAssessment: thinLiquidity,
  });
  assert.equal(liquidityBlocked.state, 'BLOCK');
  assert.ok(liquidityBlocked.reasons.includes('LIQUIDITY_HEADROOM_BLOCKED'));

  s.ledger.post({
    transaction_id: 'NEGATIVE-CUSTOMER-TEST',
    entries: [
      { account_id: 'G:CUSTOMER:001', side: 'DEBIT', amount_minor: 11000, currency: 'EUR' },
      { account_id: 'G:SUSPENSE:OUTBOUND', side: 'CREDIT', amount_minor: 11000, currency: 'EUR' },
    ],
  });
  const negative = auditSovereignInvariants({
    accounts: s.accounts,
    ledger: s.ledger,
    safeguardingAssessment: safeguarding,
    liquidityAssessment: liquidity,
  });
  assert.equal(negative.state, 'BLOCK');
  assert.ok(negative.reasons.includes('NEGATIVE_CUSTOMER_BALANCE'));

  const corrupted = { ...safeguarding, safeguarded_assets_minor: 999999 };
  assert.throws(() => auditSovereignInvariants({
    accounts: s.accounts,
    ledger: s.ledger,
    safeguardingAssessment: corrupted,
    liquidityAssessment: liquidity,
  }), /safeguarding_assessment_hash_mismatch/);

  console.log('G-BANK sovereign v2 prudential invariant tests: PASS');
})();
