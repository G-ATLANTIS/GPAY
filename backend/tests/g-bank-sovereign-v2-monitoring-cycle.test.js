'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { CustomerRegistry } = require('../g-bank-sovereign-v2/customer-registry');
const { AccountRegistry } = require('../g-bank-sovereign-v2/accounts');
const { SovereignLedger } = require('../g-bank-sovereign-v2/ledger');
const { CustomerControlService } = require('../g-bank-sovereign-v2/customer-controls');
const { EvidenceRevocationStore } = require('../g-bank-sovereign-v2/evidence-revocation-store');
const { MonitoringCaseStore } = require('../g-bank-sovereign-v2/monitoring-case-store');
const { createMonitoringPolicy } = require('../g-bank-sovereign-v2/monitoring-policy');
const { MonitoringPolicyStore } = require('../g-bank-sovereign-v2/monitoring-policy-store');
const { MonitoringCycleCoordinator } = require('../g-bank-sovereign-v2/monitoring-cycle');

const H = c => c.repeat(64);
const CUSTOMER = 'G:CUSTOMER-SUBJECT:CYCLE001';
const SUBJECT = H('1');

function hashed(body) {
  return Object.freeze({ ...body, evidence_sha256: sha256(canonicalJson(body)) });
}

function evidence(now) {
  return {
    kyc_refresh: hashed({
      schema: 'g-bank-kyc-refresh-evidence/v2',
      state: 'VERIFIED',
      subject_binding_sha256: SUBJECT,
      source: 'VERIFIED_EXTERNAL_IDENTITY_SERVICE',
      observed_at: new Date(now - 1000).toISOString(),
    }),
    sanctions_rescreen: hashed({
      schema: 'g-bank-sanctions-rescreen-evidence/v2',
      result: 'CLEAR',
      subject_binding_sha256: SUBJECT,
      source: 'VERIFIED_EXTERNAL_SCREENING_SERVICE',
      observed_at: new Date(now - 1000).toISOString(),
    }),
    pep_rescreen: hashed({
      schema: 'g-bank-pep-rescreen-evidence/v2',
      result: 'CLEAR',
      subject_binding_sha256: SUBJECT,
      source: 'VERIFIED_EXTERNAL_SCREENING_SERVICE',
      observed_at: new Date(now - 1000).toISOString(),
    }),
  };
}

function setup() {
  const now = Date.now();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-monitor-cycle-v2-'));
  const customers = new CustomerRegistry(path.join(root, 'customers.jsonl'));
  const accounts = new AccountRegistry(path.join(root, 'accounts.json'));
  const ledger = new SovereignLedger(path.join(root, 'ledger.jsonl'));
  const revocations = new EvidenceRevocationStore(path.join(root, 'revocations.jsonl'));
  const cases = new MonitoringCaseStore(path.join(root, 'cases.jsonl'));
  const policyStore = new MonitoringPolicyStore(path.join(root, 'policies'));

  customers.create({ customer_id: CUSTOMER, subject_binding_sha256: SUBJECT, now: now - 10000 });
  customers.transition({ customer_id: CUSTOMER, expected_status: 'PROSPECT', to_status: 'REVIEW', decision_evidence_sha256: H('2'), now: now - 9000 });
  customers.transition({ customer_id: CUSTOMER, expected_status: 'REVIEW', to_status: 'ACTIVE', decision_evidence_sha256: H('3'), now: now - 8000 });
  accounts.register({
    account_id: 'G:CYCLE:CUSTOMER',
    type: 'CUSTOMER',
    currency: 'EUR',
    iban: 'NL91ABNA0417164300',
    owner_binding_sha256: SUBJECT,
    metadata: { customer_id: CUSTOMER },
  });
  accounts.register({ account_id: 'G:CYCLE:SETTLEMENT', type: 'SETTLEMENT', currency: 'EUR', owner_binding_sha256: H('4') });

  const policy = createMonitoringPolicy({
    epoch: 1,
    effective_from: new Date(now - 60000).toISOString(),
    max_kyc_age_ms: 365 * 24 * 60 * 60 * 1000,
    max_screen_age_ms: 24 * 60 * 60 * 1000,
    transaction: {
      review_single_minor: 100000,
      suspend_single_minor: 500000,
      review_window_outbound_minor: 250000,
      suspend_window_outbound_minor: 1000000,
      review_transaction_count: 20,
      review_new_counterparty_count: 5,
      review_rapid_sequence_count: 5,
      suspend_rapid_sequence_count: 20,
      review_return_or_recall_count: 3,
    },
    case_review_sla_ms: { LOW: 14400000, MEDIUM: 3600000, HIGH: 900000, CRITICAL: 300000 },
  });
  policyStore.commit(policy);
  const controls = new CustomerControlService({ customers, accounts });
  const coordinator = new MonitoringCycleCoordinator({ customers, accounts, ledger, customerControls: controls, revocations, cases, policyStore });
  return { now, root, customers, accounts, ledger, revocations, cases, policyStore, coordinator };
}

(() => {
  const s = setup();
  s.ledger.post({
    transaction_id: 'CYCLE-SUSPEND-001',
    reference: 'CYCLE-SUSPEND-001',
    entries: [
      { account_id: 'G:CYCLE:CUSTOMER', side: 'DEBIT', amount_minor: 600000, currency: 'EUR' },
      { account_id: 'G:CYCLE:SETTLEMENT', side: 'CREDIT', amount_minor: 600000, currency: 'EUR' },
    ],
    metadata: { kind: 'OUTBOUND_SETTLEMENT', beneficiary_binding_sha256: H('a') },
  });
  const result = s.coordinator.run({
    evidenceByCustomer: { [CUSTOMER]: evidence(s.now) },
    currency: 'EUR',
    window_start: new Date(s.now - 60000).toISOString(),
    window_end: new Date(s.now + 5000).toISOString(),
    enforce: true,
    now: s.now + 5000,
  });
  assert.equal(result.cycle.state, 'PASS');
  assert.equal(result.fleetAudit.state, 'PASS');
  assert.equal(result.enforcements.length, 1);
  assert.equal(result.enforcements[0].customer_suspension_performed, true);
  assert.equal(s.customers.get(CUSTOMER).status, 'SUSPENDED');
  assert.equal(s.accounts.get('G:CYCLE:CUSTOMER').status, 'SUSPENDED');
  assert.equal(result.cycle.automatic_reactivation_performed, false);
  assert.equal(result.cycle.regulatory_determination_made, false);
  assert.equal(result.cycle.external_report_submitted, false);
  assert.equal(result.cycle.external_payment_action_performed, false);
  assert.equal(result.cycle.value_moved, false);
  assert.match(result.cycle.policy_store_root_sha256, /^[0-9a-f]{64}$/);
  assert.match(result.cycle.cycle_sha256, /^[0-9a-f]{64}$/);
})();

(() => {
  const s = setup();
  s.ledger.post({
    transaction_id: 'CYCLE-DRYRUN-001',
    reference: 'CYCLE-DRYRUN-001',
    entries: [
      { account_id: 'G:CYCLE:CUSTOMER', side: 'DEBIT', amount_minor: 600000, currency: 'EUR' },
      { account_id: 'G:CYCLE:SETTLEMENT', side: 'CREDIT', amount_minor: 600000, currency: 'EUR' },
    ],
    metadata: { kind: 'OUTBOUND_SETTLEMENT', beneficiary_binding_sha256: H('b') },
  });
  const result = s.coordinator.run({
    evidenceByCustomer: { [CUSTOMER]: evidence(s.now) },
    currency: 'EUR',
    window_start: new Date(s.now - 60000).toISOString(),
    window_end: new Date(s.now + 5000).toISOString(),
    enforce: false,
    now: s.now + 5000,
  });
  assert.equal(result.cycle.state, 'BLOCK');
  assert.equal(result.fleetAudit.state, 'BLOCK');
  assert(result.fleetAudit.reasons.some(reason => reason.startsWith('UNENFORCED_SUSPEND_REQUIRED:')));
  assert.equal(s.customers.get(CUSTOMER).status, 'ACTIVE');
  assert.equal(result.enforcements.length, 0);
})();

console.log('G-BANK sovereign v2 monitoring cycle tests: PASS');
