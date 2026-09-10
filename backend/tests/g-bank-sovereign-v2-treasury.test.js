'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { AccountRegistry } = require('../g-bank-sovereign-v2/accounts');
const { SovereignLedger } = require('../g-bank-sovereign-v2/ledger');
const { assessSafeguarding } = require('../g-bank-sovereign-v2/safeguarding');
const { assessLiquidity } = require('../g-bank-sovereign-v2/liquidity');
const { auditSovereignInvariants } = require('../g-bank-sovereign-v2/invariant-auditor');
const { assessOperationalResilience } = require('../g-bank-sovereign-v2/operational-resilience');
const { assessTreasuryPosition, verifySettlementLiquidityEvidence } = require('../g-bank-sovereign-v2/treasury-position');
const { snapshotState } = require('../g-bank-sovereign-v2/checkpoint');
const { createEndOfDayClose } = require('../g-bank-sovereign-v2/eod-close');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T20:00:00.000Z');

function liquidityEvidence(available_minor) {
  const body = {
    schema: 'g-bank-settlement-liquidity-evidence/v2',
    state: 'VERIFIED',
    source: 'VERIFIED_EXTERNAL_READBACK',
    currency: 'EUR',
    available_minor,
    settlement_system: 'AUTHORIZED-TEST-BOUNDARY',
    account_binding_sha256: H('a'),
    observed_at: new Date(NOW - 30000).toISOString(),
  };
  return Object.freeze({ ...body, evidence_sha256: sha256(canonicalJson(body)) });
}

function setup() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-treasury-v2-'));
  const accountsPath = path.join(root, 'accounts.json');
  const ledgerPath = path.join(root, 'ledger.jsonl');
  const receiptsPath = path.join(root, 'receipts.jsonl');
  const executionsDir = path.join(root, 'executions');
  const accounts = new AccountRegistry(accountsPath);
  const ledger = new SovereignLedger(ledgerPath);

  for (const account of [
    { account_id: 'G:TREASURY:001', type: 'TREASURY', iban: null, owner: H('1') },
    { account_id: 'G:CUSTOMER:001', type: 'CUSTOMER', iban: 'NL91ABNA0417164300', owner: H('2') },
    { account_id: 'G:SAFEGUARD:001', type: 'SAFEGUARDING', iban: null, owner: H('3') },
    { account_id: 'G:SUSPENSE:OUTBOUND', type: 'SUSPENSE', iban: null, owner: H('4') },
    { account_id: 'G:SETTLEMENT:OUTBOUND', type: 'SETTLEMENT', iban: null, owner: H('5') },
  ]) {
    accounts.register({ ...account, currency: 'EUR', owner_binding_sha256: account.owner });
  }

  ledger.post({
    transaction_id: 'TREASURY-OPEN-001',
    reference: 'OPENING',
    entries: [
      { account_id: 'G:TREASURY:001', side: 'DEBIT', amount_minor: 20000, currency: 'EUR' },
      { account_id: 'G:CUSTOMER:001', side: 'CREDIT', amount_minor: 10000, currency: 'EUR' },
      { account_id: 'G:SAFEGUARD:001', side: 'CREDIT', amount_minor: 10000, currency: 'EUR' },
    ],
  });

  return { root, accountsPath, ledgerPath, receiptsPath, executionsDir, accounts, ledger };
}

(() => {
  const s = setup();
  const safeguarding = assessSafeguarding({
    customer_liabilities_minor: 10000,
    safeguarded_assets_minor: 12000,
    required_buffer_minor: 1000,
    evidence_sha256: H('b'),
    now: NOW,
  });
  const liquidity = assessLiquidity({
    immediately_available_minor: 10000,
    pending_outbound_minor: 0,
    stressed_outflow_minor: 2000,
    minimum_buffer_minor: 1000,
    now: NOW,
  });
  const invariant = auditSovereignInvariants({
    accounts: s.accounts,
    ledger: s.ledger,
    safeguardingAssessment: safeguarding,
    liquidityAssessment: liquidity,
    now: NOW,
  });
  assert.equal(invariant.state, 'PASS');

  const evidence = liquidityEvidence(10000);
  const verifiedEvidence = verifySettlementLiquidityEvidence(evidence, { currency: 'EUR', now: NOW });
  assert.equal(verifiedEvidence.available_minor, 10000);

  const treasury = assessTreasuryPosition({
    accounts: s.accounts,
    ledger: s.ledger,
    settlementLiquidityEvidence: evidence,
    minimum_prefunding_minor: 2000,
    reserve_buffer_minor: 1000,
    stressed_outflow_minor: 2000,
    now: NOW,
  });
  assert.equal(treasury.state, 'PASS');
  assert.equal(treasury.required_settlement_liquidity_minor, 5000);
  assert.equal(treasury.settlement_headroom_minor, 5000);

  const checkpoint = snapshotState({
    accountRegistryPath: s.accountsPath,
    ledgerPath: s.ledgerPath,
    receiptsPath: s.receiptsPath,
    executionsDir: s.executionsDir,
    now: NOW,
  });
  const resilience = assessOperationalResilience({
    ledger_verified: true,
    receipt_chain_verified: true,
    checkpoint_verified: true,
    unresolved_unknown_count: 0,
    max_unresolved_unknown: 0,
    clock_drift_ms: 10,
    max_clock_drift_ms: 5000,
    emergency_freeze: false,
    now: NOW,
  });
  assert.equal(resilience.state, 'PASS');

  const close = createEndOfDayClose({
    business_date: '2026-09-10',
    checkpoint,
    invariantAudit: invariant,
    safeguardingAssessment: safeguarding,
    liquidityAssessment: liquidity,
    treasuryAssessment: treasury,
    resilienceAssessment: resilience,
    now: NOW,
  });
  assert.equal(close.state, 'CLOSED');
  assert.match(close.close_sha256, /^[0-9a-f]{64}$/);

  const constrained = assessTreasuryPosition({
    accounts: s.accounts,
    ledger: s.ledger,
    settlementLiquidityEvidence: liquidityEvidence(3000),
    minimum_prefunding_minor: 2000,
    reserve_buffer_minor: 1000,
    stressed_outflow_minor: 2000,
    now: NOW,
  });
  assert.equal(constrained.state, 'BLOCK');
  assert.equal(constrained.settlement_headroom_minor, -2000);

  const blockedClose = createEndOfDayClose({
    business_date: '2026-09-10',
    checkpoint,
    invariantAudit: invariant,
    safeguardingAssessment: safeguarding,
    liquidityAssessment: liquidity,
    treasuryAssessment: constrained,
    resilienceAssessment: resilience,
    now: NOW,
  });
  assert.equal(blockedClose.state, 'BLOCK');
  assert(blockedClose.reasons.includes('TREASURY_BLOCKED'));

  const tamperedEvidence = { ...evidence, available_minor: 999999 };
  assert.throws(() => verifySettlementLiquidityEvidence(tamperedEvidence, { currency: 'EUR', now: NOW }), /hash_mismatch/);

  const frozen = assessOperationalResilience({
    ledger_verified: true,
    receipt_chain_verified: true,
    checkpoint_verified: true,
    emergency_freeze: true,
    now: NOW,
  });
  const frozenClose = createEndOfDayClose({
    business_date: '2026-09-10',
    checkpoint,
    invariantAudit: invariant,
    safeguardingAssessment: safeguarding,
    liquidityAssessment: liquidity,
    treasuryAssessment: treasury,
    resilienceAssessment: frozen,
    now: NOW,
  });
  assert.equal(frozenClose.state, 'BLOCK');
  assert(frozenClose.reasons.includes('RESILIENCE_BLOCKED'));

  console.log('G-BANK sovereign v2 treasury/EOD tests: PASS');
})();
