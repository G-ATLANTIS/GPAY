'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { AccountRegistry } = require('../g-bank-sovereign-v2/accounts');
const { SovereignLedger } = require('../g-bank-sovereign-v2/ledger');
const { InboundStore } = require('../g-bank-sovereign-v2/inbound-store');
const { InboundPaymentProcessor } = require('../g-bank-sovereign-v2/inbound-payments');
const { createAccountBalanceView } = require('../g-bank-sovereign-v2/account-balance-view');
const { createAccountStatement } = require('../g-bank-sovereign-v2/account-statements');
const { createReturnRequest, createRecallDecision } = require('../g-bank-sovereign-v2/inbound-exceptions');
const { AccountLifecycle } = require('../g-bank-sovereign-v2/account-lifecycle');

const H = c => c.repeat(64);
const NOW = Date.now();

function hashObject(body, field) {
  return Object.freeze({ ...body, [field]: sha256(canonicalJson(body)) });
}

function inboundEvent({ id = 'IN-001', amount = 5000, iban = 'NL91ABNA0417164300', observed = NOW - 1000 } = {}) {
  return hashObject({
    schema: 'g-bank-inbound-settlement-evidence/v2',
    source: 'VERIFIED_EXTERNAL_READBACK',
    status: 'SETTLED',
    scheme: 'SCT_INST',
    inbound_id: id,
    amount_minor: amount,
    currency: 'EUR',
    creditor_iban: iban,
    settlement_system: 'AUTHORIZED-TEST-BOUNDARY',
    settlement_reference: `SETTLE-${id}`,
    external_receipt_sha256: H('a'),
    observed_at: new Date(observed).toISOString(),
  }, 'event_sha256');
}

function releaseEvidence(current, now = NOW) {
  return hashObject({
    schema: 'g-bank-inbound-release-evidence/v2',
    state: 'PASS',
    inbound_id: current.inbound_id,
    inbound_event_sha256: current.event_sha256,
    target_account_id: current.target_account_id,
    amount_minor: current.amount_minor,
    currency: current.currency,
    verified_at: new Date(now - 500).toISOString(),
  }, 'release_sha256');
}

function setup() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-inbound-v2-'));
  const accounts = new AccountRegistry(path.join(root, 'accounts.json'));
  const ledger = new SovereignLedger(path.join(root, 'ledger.jsonl'));
  const inboundStore = new InboundStore(path.join(root, 'inbound.jsonl'));
  accounts.register({ account_id: 'G:CUSTOMER:001', type: 'CUSTOMER', currency: 'EUR', iban: 'NL91ABNA0417164300', owner_binding_sha256: H('1') });
  accounts.register({ account_id: 'G:CUSTOMER:ZERO', type: 'CUSTOMER', currency: 'EUR', iban: 'NL02ABNA0123456789', owner_binding_sha256: H('2') });
  accounts.register({ account_id: 'G:SETTLEMENT:INBOUND', type: 'SETTLEMENT', currency: 'EUR', owner_binding_sha256: H('3') });
  accounts.register({ account_id: 'G:SUSPENSE:INBOUND', type: 'SUSPENSE', currency: 'EUR', owner_binding_sha256: H('4') });
  const processor = new InboundPaymentProcessor({
    accounts,
    ledger,
    inboundStore,
    settlement_account_id: 'G:SETTLEMENT:INBOUND',
    inbound_suspense_account_id: 'G:SUSPENSE:INBOUND',
  });
  return { root, accounts, ledger, inboundStore, processor };
}

(() => {
  const s = setup();
  const event = inboundEvent();
  const pending = s.processor.ingest(event, { now: NOW });
  assert.equal(pending.state, 'PENDING');
  assert.equal(pending.settlement_business_date, new Date(event.observed_at).toISOString().slice(0, 10));
  assert.equal(s.ledger.balance('G:CUSTOMER:001', 'EUR'), 0);
  assert.equal(s.ledger.balance('G:SUSPENSE:INBOUND', 'EUR'), 5000);
  assert.equal(s.ledger.records().length, 1);

  const duplicate = s.processor.ingest(event, { now: NOW + 100 });
  assert.equal(duplicate.state, 'PENDING');
  assert.equal(s.ledger.records().length, 1, 'duplicate inbound must not double book');

  const conflicting = inboundEvent({ id: 'IN-001', amount: 6000 });
  assert.throws(() => s.processor.ingest(conflicting, { now: NOW }), /inbound_id_reused_for_different_event/);

  const balancePending = createAccountBalanceView({
    accounts: s.accounts, ledger: s.ledger, inboundStore: s.inboundStore, account_id: 'G:CUSTOMER:001', now: NOW,
  });
  assert.equal(balancePending.available_balance_minor, 0);
  assert.equal(balancePending.pending_inbound_minor, 5000);
  assert.equal(balancePending.projected_balance_minor, 5000);

  const release = releaseEvidence(pending);
  const available = s.processor.makeAvailable({ inbound_id: 'IN-001', releaseEvidence: release, now: NOW });
  assert.equal(available.state, 'AVAILABLE');
  assert.equal(s.ledger.balance('G:CUSTOMER:001', 'EUR'), 5000);
  assert.equal(s.ledger.balance('G:SUSPENSE:INBOUND', 'EUR'), 0);
  assert.equal(s.ledger.records().length, 2);

  const duplicateRelease = s.processor.makeAvailable({ inbound_id: 'IN-001', releaseEvidence: release, now: NOW + 100 });
  assert.equal(duplicateRelease.state, 'AVAILABLE');
  assert.equal(s.ledger.records().length, 2, 'duplicate release must not double credit');

  const balanceAvailable = createAccountBalanceView({
    accounts: s.accounts, ledger: s.ledger, inboundStore: s.inboundStore, account_id: 'G:CUSTOMER:001', now: NOW,
  });
  assert.equal(balanceAvailable.available_balance_minor, 5000);
  assert.equal(balanceAvailable.pending_inbound_minor, 0);

  const returnRequest = createReturnRequest({ inboundRecord: available, reason_code: 'AC01', operator_evidence_sha256: H('b'), now: NOW });
  assert.equal(returnRequest.state, 'REQUESTED_NOT_SUBMITTED');
  assert.equal(returnRequest.external_submission_performed, false);
  assert.equal(returnRequest.value_moved, false);

  const recall = createRecallDecision({ inboundRecord: available, decision: 'REJECT', operator_evidence_sha256: H('c'), now: NOW });
  assert.equal(recall.state, 'DECIDED_NOT_SUBMITTED');
  assert.equal(recall.external_submission_performed, false);
  assert.equal(recall.value_moved, false);

  const from = new Date(NOW - 60 * 1000).toISOString();
  const to = new Date(NOW + 30 * 1000).toISOString();
  const statement = createAccountStatement({ accounts: s.accounts, ledger: s.ledger, account_id: 'G:CUSTOMER:001', from, to, now: NOW + 30 * 1000 });
  assert.equal(statement.closing_balance_minor, 5000);
  assert.equal(statement.entry_count, 1);
  assert.match(statement.statement_sha256, /^[0-9a-f]{64}$/);

  const lifecycle = new AccountLifecycle({ accounts: s.accounts, ledger: s.ledger, inboundStore: s.inboundStore });
  const suspended = lifecycle.suspend({ account_id: 'G:CUSTOMER:001', evidence_sha256: H('d'), now: NOW });
  assert.equal(suspended.status, 'SUSPENDED');
  assert.throws(() => lifecycle.close({ account_id: 'G:CUSTOMER:001', evidence_sha256: H('e'), now: NOW }), /zero_balance/);
  const reactivated = lifecycle.reactivate({ account_id: 'G:CUSTOMER:001', evidence_sha256: H('f'), now: NOW });
  assert.equal(reactivated.status, 'ACTIVE');

  lifecycle.suspend({ account_id: 'G:CUSTOMER:ZERO', evidence_sha256: H('1'), now: NOW });
  const closed = lifecycle.close({ account_id: 'G:CUSTOMER:ZERO', evidence_sha256: H('2'), now: NOW });
  assert.equal(closed.status, 'CLOSED');
  assert.throws(() => s.processor.ingest(inboundEvent({ id: 'IN-CLOSED', iban: 'NL02ABNA0123456789' }), { now: NOW }), /not_active/);

  const pending2 = s.processor.ingest(inboundEvent({ id: 'IN-002', amount: 700 }), { now: NOW });
  lifecycle.suspend({ account_id: 'G:CUSTOMER:001', evidence_sha256: H('3'), now: NOW });
  assert.throws(() => lifecycle.close({ account_id: 'G:CUSTOMER:001', evidence_sha256: H('4'), now: NOW }), /pending_inbound/);
  assert.throws(() => s.processor.makeAvailable({ inbound_id: 'IN-002', releaseEvidence: releaseEvidence(pending2), now: NOW }), /account_not_active/);

  const tamperedRelease = { ...releaseEvidence(pending2), amount_minor: 701 };
  assert.throws(() => s.processor.makeAvailable({ inbound_id: 'IN-002', releaseEvidence: tamperedRelease, now: NOW }), /hash_mismatch/);

  console.log('G-BANK sovereign v2 inbound/account lifecycle tests: PASS');
})();

(() => {
  const s = setup();
  const event = inboundEvent({ id: 'IN-CRASH', amount: 900 });
  const target = s.accounts.findByIban(event.creditor_iban);
  const claim = s.inboundStore.claim({
    inbound_id: event.inbound_id,
    event_sha256: event.event_sha256,
    target_account_id: target.account_id,
    amount_minor: event.amount_minor,
    currency: event.currency,
    settlement_business_date: new Date(event.observed_at).toISOString().slice(0, 10),
    now: NOW,
  });
  assert.equal(claim.record.state, 'CLAIMED');
  const txid = `INBOUND:PENDING:${sha256(`${event.inbound_id}:${event.event_sha256}`).slice(0, 32)}`;
  s.ledger.post({
    transaction_id: txid,
    reference: event.inbound_id,
    entries: [
      { account_id: 'G:SETTLEMENT:INBOUND', side: 'DEBIT', amount_minor: 900, currency: 'EUR' },
      { account_id: 'G:SUSPENSE:INBOUND', side: 'CREDIT', amount_minor: 900, currency: 'EUR' },
    ],
    metadata: {
      kind: 'INBOUND_SETTLEMENT_PENDING',
      inbound_id: event.inbound_id,
      inbound_event_sha256: event.event_sha256,
      settlement_business_date: new Date(event.observed_at).toISOString().slice(0, 10),
      target_account_id: target.account_id,
    },
  });
  const recovered = s.processor.ingest(event, { now: NOW + 1000 });
  assert.equal(recovered.state, 'PENDING');
  assert.equal(s.ledger.records().length, 1, 'crash recovery must reuse existing deterministic ledger booking');
})();
