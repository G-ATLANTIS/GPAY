'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { CustomerRegistry } = require('../g-bank-sovereign-v2/customer-registry');
const { AccountRegistry } = require('../g-bank-sovereign-v2/accounts');
const { CustomerControlService } = require('../g-bank-sovereign-v2/customer-controls');
const { EvidenceRevocationStore } = require('../g-bank-sovereign-v2/evidence-revocation-store');
const { MonitoringCaseStore } = require('../g-bank-sovereign-v2/monitoring-case-store');
const { assessTransactionActivity } = require('../g-bank-sovereign-v2/transaction-monitoring');
const { ContinuousCustomerMonitoringService } = require('../g-bank-sovereign-v2/continuous-customer-monitoring');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T08:40:00.000Z');
const CUSTOMER = 'G:CUSTOMER-SUBJECT:MON001';
const SUBJECT = H('1');

function hashed(body, field = 'evidence_sha256') {
  return Object.freeze({ ...body, [field]: sha256(canonicalJson(body)) });
}

function monitoringEvidence({ kycObserved = NOW - 1000, screenObserved = NOW - 1000 } = {}) {
  return {
    kyc_refresh: hashed({
      schema: 'g-bank-kyc-refresh-evidence/v2',
      state: 'VERIFIED',
      subject_binding_sha256: SUBJECT,
      source: 'VERIFIED_EXTERNAL_IDENTITY_SERVICE',
      observed_at: new Date(kycObserved).toISOString(),
    }),
    sanctions_rescreen: hashed({
      schema: 'g-bank-sanctions-rescreen-evidence/v2',
      result: 'CLEAR',
      subject_binding_sha256: SUBJECT,
      source: 'VERIFIED_EXTERNAL_SCREENING_SERVICE',
      observed_at: new Date(screenObserved).toISOString(),
    }),
    pep_rescreen: hashed({
      schema: 'g-bank-pep-rescreen-evidence/v2',
      result: 'CLEAR',
      subject_binding_sha256: SUBJECT,
      source: 'VERIFIED_EXTERNAL_SCREENING_SERVICE',
      observed_at: new Date(screenObserved).toISOString(),
    }),
  };
}

const policy = {
  review_single_minor: 100000,
  suspend_single_minor: 500000,
  review_window_outbound_minor: 250000,
  suspend_window_outbound_minor: 1000000,
  review_transaction_count: 20,
  review_new_counterparty_count: 5,
  review_rapid_sequence_count: 5,
  suspend_rapid_sequence_count: 20,
  review_return_or_recall_count: 3,
};

function txAssessment({ max = 1000, outbound = 1000, count = 1, rapid = 0 } = {}) {
  return assessTransactionActivity({
    customer_id: CUSTOMER,
    currency: 'EUR',
    window_start: new Date(NOW - 60 * 60 * 1000).toISOString(),
    window_end: new Date(NOW - 1000).toISOString(),
    transaction_count: count,
    total_inbound_minor: 0,
    total_outbound_minor: outbound,
    max_single_transaction_minor: max,
    distinct_counterparty_count: 1,
    new_counterparty_count: 1,
    rapid_sequence_count: rapid,
    return_or_recall_count: 0,
    source_root_sha256: H('9'),
    policy,
    now: NOW,
  });
}

function setup() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-monitor-v2-'));
  const customers = new CustomerRegistry(path.join(root, 'customers.jsonl'));
  const accounts = new AccountRegistry(path.join(root, 'accounts.json'));
  const revocations = new EvidenceRevocationStore(path.join(root, 'revocations.jsonl'));
  const cases = new MonitoringCaseStore(path.join(root, 'cases.jsonl'));

  customers.create({ customer_id: CUSTOMER, subject_binding_sha256: SUBJECT, now: NOW - 10000 });
  customers.transition({ customer_id: CUSTOMER, expected_status: 'PROSPECT', to_status: 'REVIEW', decision_evidence_sha256: H('2'), now: NOW - 9000 });
  customers.transition({ customer_id: CUSTOMER, expected_status: 'REVIEW', to_status: 'ACTIVE', decision_evidence_sha256: H('3'), now: NOW - 8000 });

  accounts.register({
    account_id: 'G:MONITOR:001',
    type: 'CUSTOMER',
    currency: 'EUR',
    iban: 'NL91ABNA0417164300',
    owner_binding_sha256: SUBJECT,
    metadata: { customer_id: CUSTOMER },
  });

  const controls = new CustomerControlService({ customers, accounts });
  const monitor = new ContinuousCustomerMonitoringService({ customers, customerControls: controls, revocations, cases });
  return { root, customers, accounts, revocations, cases, controls, monitor };
}

(() => {
  const s = setup();
  const evidence = monitoringEvidence();

  const clear = s.monitor.assess({ customer_id: CUSTOMER, monitoringEvidence: evidence, transactionAssessment: txAssessment(), now: NOW });
  assert.equal(clear.state, 'CLEAR');
  const clearEnforcement = s.monitor.enforce(clear, { now: NOW });
  assert.equal(clearEnforcement.customer_suspension_performed, false);
  assert.equal(clearEnforcement.monitoring_case_id, null);
  assert.equal(s.customers.get(CUSTOMER).status, 'ACTIVE');

  const reviewTx = txAssessment({ max: 150000 });
  assert.equal(reviewTx.state, 'REVIEW_REQUIRED');
  const review = s.monitor.assess({ customer_id: CUSTOMER, monitoringEvidence: evidence, transactionAssessment: reviewTx, now: NOW });
  assert.equal(review.state, 'REVIEW_REQUIRED');
  const reviewEnforcement = s.monitor.enforce(review, { now: NOW });
  assert.equal(reviewEnforcement.customer_suspension_performed, false);
  assert.ok(reviewEnforcement.monitoring_case_id);
  assert.equal(s.customers.get(CUSTOMER).status, 'ACTIVE');
  assert.equal(s.cases.list({ customer_id: CUSTOMER }).length, 1);
  assert.equal(s.monitor.enforce(review, { now: NOW + 1 }).monitoring_case_id, reviewEnforcement.monitoring_case_id, 'review enforcement must be idempotent');

  const suspendTx = txAssessment({ max: 600000 });
  assert.equal(suspendTx.state, 'SUSPEND_REQUIRED');
  const suspend = s.monitor.assess({ customer_id: CUSTOMER, monitoringEvidence: evidence, transactionAssessment: suspendTx, now: NOW });
  assert.equal(suspend.state, 'SUSPEND_REQUIRED');
  const enforced = s.monitor.enforce(suspend, { now: NOW });
  assert.equal(enforced.customer_suspension_performed, true);
  assert.equal(s.customers.get(CUSTOMER).status, 'SUSPENDED');
  assert.equal(s.accounts.get('G:MONITOR:001').status, 'SUSPENDED');
  assert.equal(enforced.external_action_performed, false);
  assert.equal(enforced.value_moved, false);

  const clearWhileSuspended = s.monitor.assess({ customer_id: CUSTOMER, monitoringEvidence: evidence, transactionAssessment: txAssessment(), now: NOW });
  assert.equal(clearWhileSuspended.state, 'REVIEW_REQUIRED', 'existing open cases keep review state');
  const noReactivate = s.monitor.enforce(clearWhileSuspended, { now: NOW });
  assert.equal(noReactivate.automatic_reactivation_performed, false);
  assert.equal(s.customers.get(CUSTOMER).status, 'SUSPENDED');

  const tamperedTx = { ...txAssessment(), transaction_count: 999 };
  assert.throws(() => s.monitor.assess({ customer_id: CUSTOMER, monitoringEvidence: evidence, transactionAssessment: tamperedTx, now: NOW }), /hash_mismatch/);
})();

(() => {
  const s = setup();
  const evidence = monitoringEvidence();
  s.revocations.revoke({
    evidence_sha256: evidence.kyc_refresh.evidence_sha256,
    revocation_evidence_sha256: H('a'),
    reason: 'UPSTREAM_EVIDENCE_WITHDRAWN',
    now: NOW,
  });
  assert.equal(s.revocations.isRevoked(evidence.kyc_refresh.evidence_sha256), true);
  const assessment = s.monitor.assess({ customer_id: CUSTOMER, monitoringEvidence: evidence, now: NOW });
  assert.equal(assessment.state, 'SUSPEND_REQUIRED');
  assert(assessment.reasons.includes('MONITORING_EVIDENCE_REVOKED'));
  s.monitor.enforce(assessment, { now: NOW });
  assert.equal(s.customers.get(CUSTOMER).status, 'SUSPENDED');
})();

(() => {
  const s = setup();
  const stale = monitoringEvidence({ screenObserved: NOW - (25 * 60 * 60 * 1000) });
  const assessment = s.monitor.assess({ customer_id: CUSTOMER, monitoringEvidence: stale, now: NOW });
  assert.equal(assessment.state, 'SUSPEND_REQUIRED');
  assert(assessment.reasons.some(reason => reason.includes('stale')));
})();

(() => {
  const s = setup();
  const critical = s.cases.open({
    customer_id: CUSTOMER,
    signal_sha256: H('b'),
    severity: 'CRITICAL',
    reason_code: 'MANUAL_CRITICAL_CONTROL_SIGNAL',
    now: NOW,
  });
  assert.equal(critical.status, 'OPEN');
  const assessment = s.monitor.assess({ customer_id: CUSTOMER, monitoringEvidence: monitoringEvidence(), now: NOW });
  assert.equal(assessment.state, 'SUSPEND_REQUIRED');
  const reviewed = s.cases.transition({ case_id: critical.case_id, expected_status: 'OPEN', to_status: 'UNDER_REVIEW', decision_evidence_sha256: H('c'), now: NOW });
  assert.equal(reviewed.status, 'UNDER_REVIEW');
  assert.equal(reviewed.regulatory_suspicion_determined, false);
  assert.equal(reviewed.external_report_submitted, false);
})();

console.log('G-BANK sovereign v2 continuous monitoring tests: PASS');
