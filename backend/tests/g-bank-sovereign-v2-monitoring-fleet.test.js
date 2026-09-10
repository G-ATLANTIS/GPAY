'use strict';

const assert = require('node:assert/strict');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { createMonitoringPolicy } = require('../g-bank-sovereign-v2/monitoring-policy');
const { auditMonitoringFleet } = require('../g-bank-sovereign-v2/monitoring-fleet-audit');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T08:50:00.000Z');
const policy = createMonitoringPolicy({
  epoch: 4,
  effective_from: '2026-09-10T00:00:00.000Z',
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

function assessment(customer, state = 'CLEAR', assessedAt = NOW - 1000) {
  const body = {
    schema: 'g-bank-continuous-customer-monitoring-assessment/v2',
    state,
    customer_id: customer.customer_id,
    customer_status: customer.status,
    customer_record_sha256: customer.record_sha256,
    policy_sha256: policy.policy_sha256,
    policy_epoch: policy.epoch,
    monitoring_proof_sha256: H('2'),
    transaction_assessment_sha256: H('3'),
    case_sla_assessment_sha256: H('4'),
    open_case_ids: [],
    reasons: [],
    assessed_at: new Date(assessedAt).toISOString(),
    regulatory_suspicion_determined: false,
    external_report_submitted: false,
    reactivation_performed: false,
    permits_value_movement: false,
  };
  return Object.freeze({ ...body, assessment_sha256: sha256(canonicalJson(body)) });
}

const active = { customer_id: 'G:CUSTOMER-SUBJECT:FLEET001', status: 'ACTIVE', record_sha256: H('a') };
const suspended = { customer_id: 'G:CUSTOMER-SUBJECT:FLEET002', status: 'SUSPENDED', record_sha256: H('b') };
const customers = { list: () => [active, suspended] };
const safeAccounts = { list: () => [
  { account_id: 'G:FLEET:1', type: 'CUSTOMER', status: 'ACTIVE', metadata: { customer_id: active.customer_id } },
  { account_id: 'G:FLEET:2', type: 'CUSTOMER', status: 'SUSPENDED', metadata: { customer_id: suspended.customer_id } },
] };

const pass = auditMonitoringFleet({
  customers,
  accounts: safeAccounts,
  assessments: [assessment(active, 'REVIEW_REQUIRED'), assessment(suspended, 'SUSPEND_REQUIRED')],
  monitoringPolicy: policy,
  now: NOW,
});
assert.equal(pass.state, 'PASS');
assert.equal(pass.review_required_customer_count, 1);
assert.equal(pass.suspended_customer_count, 1);
assert.match(pass.audit_sha256, /^[0-9a-f]{64}$/);

const missing = auditMonitoringFleet({ customers, accounts: safeAccounts, assessments: [assessment(active)], monitoringPolicy: policy, now: NOW });
assert.equal(missing.state, 'BLOCK');
assert(missing.reasons.some(reason => reason.startsWith('MISSING_MONITORING_ASSESSMENT:')));

const unenforced = auditMonitoringFleet({
  customers,
  accounts: safeAccounts,
  assessments: [assessment(active, 'SUSPEND_REQUIRED'), assessment(suspended, 'SUSPEND_REQUIRED')],
  monitoringPolicy: policy,
  now: NOW,
});
assert.equal(unenforced.state, 'BLOCK');
assert(unenforced.reasons.some(reason => reason.startsWith('UNENFORCED_SUSPEND_REQUIRED:')));

const unsafeAccounts = { list: () => [
  { account_id: 'G:FLEET:1', type: 'CUSTOMER', status: 'ACTIVE', metadata: { customer_id: active.customer_id } },
  { account_id: 'G:FLEET:2', type: 'CUSTOMER', status: 'ACTIVE', metadata: { customer_id: suspended.customer_id } },
] };
const accountLeak = auditMonitoringFleet({
  customers,
  accounts: unsafeAccounts,
  assessments: [assessment(active), assessment(suspended, 'SUSPEND_REQUIRED')],
  monitoringPolicy: policy,
  now: NOW,
});
assert.equal(accountLeak.state, 'BLOCK');
assert(accountLeak.reasons.some(reason => reason.startsWith('SUSPENDED_CUSTOMER_HAS_ACTIVE_ACCOUNT:')));

const stale = auditMonitoringFleet({
  customers,
  accounts: safeAccounts,
  assessments: [assessment(active, 'CLEAR', NOW - 16 * 60 * 1000), assessment(suspended, 'SUSPEND_REQUIRED')],
  monitoringPolicy: policy,
  now: NOW,
});
assert.equal(stale.state, 'BLOCK');
assert(stale.reasons.some(reason => reason.startsWith('MONITORING_ASSESSMENT_STALE:')));

const tampered = { ...assessment(active), state: 'SUSPEND_REQUIRED' };
assert.throws(() => auditMonitoringFleet({ customers, accounts: safeAccounts, assessments: [tampered, assessment(suspended)], monitoringPolicy: policy, now: NOW }), /assessment_hash_mismatch/);

console.log('G-BANK sovereign v2 monitoring fleet audit tests: PASS');
