'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { verifyMonitoringPolicy } = require('./monitoring-policy');

function verifyAssessment(value) {
  if (!value || value.schema !== 'g-bank-continuous-customer-monitoring-assessment/v2') throw new Error('monitoring_fleet_assessment_invalid');
  const supplied = String(value.assessment_sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) throw new Error('monitoring_fleet_assessment_hash_invalid');
  const { assessment_sha256, ...body } = value;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('monitoring_fleet_assessment_hash_mismatch');
  if (!['CLEAR', 'REVIEW_REQUIRED', 'SUSPEND_REQUIRED'].includes(value.state)) throw new Error('monitoring_fleet_assessment_state_invalid');
  return value;
}

function auditMonitoringFleet({
  customers,
  accounts,
  assessments,
  monitoringPolicy,
  now = Date.now(),
  max_assessment_age_ms = 15 * 60 * 1000,
}) {
  if (!customers || typeof customers.list !== 'function') throw new Error('monitoring_fleet_customers_required');
  if (!accounts || typeof accounts.list !== 'function') throw new Error('monitoring_fleet_accounts_required');
  if (!Array.isArray(assessments)) throw new Error('monitoring_fleet_assessments_required');
  const policy = verifyMonitoringPolicy(monitoringPolicy, { now });
  const maxAge = Number(max_assessment_age_ms);
  if (!Number.isSafeInteger(maxAge) || maxAge <= 0) throw new Error('monitoring_fleet_max_age_invalid');

  const monitorable = customers.list().filter(customer => ['ACTIVE', 'SUSPENDED'].includes(customer.status));
  const accountRows = accounts.list({ type: 'CUSTOMER' });
  const assessmentMap = new Map();
  const reasons = [];

  for (const raw of assessments) {
    const assessment = verifyAssessment(raw);
    if (assessmentMap.has(assessment.customer_id)) throw new Error('monitoring_fleet_duplicate_customer_assessment');
    assessmentMap.set(assessment.customer_id, assessment);
  }

  let clearCount = 0;
  let reviewCount = 0;
  let suspendedCount = 0;
  for (const customer of monitorable) {
    const assessment = assessmentMap.get(customer.customer_id);
    if (!assessment) {
      reasons.push(`MISSING_MONITORING_ASSESSMENT:${customer.customer_id}`);
      continue;
    }
    if (assessment.customer_record_sha256 !== customer.record_sha256) reasons.push(`CUSTOMER_STATE_BINDING_MISMATCH:${customer.customer_id}`);
    if (assessment.policy_sha256 !== policy.policy_sha256 || assessment.policy_epoch !== policy.epoch) reasons.push(`MONITORING_POLICY_BINDING_MISMATCH:${customer.customer_id}`);
    const assessedAt = Date.parse(assessment.assessed_at);
    if (!Number.isFinite(assessedAt) || assessedAt > now + 30000 || now - assessedAt > maxAge) reasons.push(`MONITORING_ASSESSMENT_STALE:${customer.customer_id}`);

    if (assessment.state === 'CLEAR') clearCount += 1;
    if (assessment.state === 'REVIEW_REQUIRED') reviewCount += 1;
    if (customer.status === 'SUSPENDED') suspendedCount += 1;

    if (customer.status === 'ACTIVE' && assessment.state === 'SUSPEND_REQUIRED') {
      reasons.push(`UNENFORCED_SUSPEND_REQUIRED:${customer.customer_id}`);
    }
    if (customer.status === 'SUSPENDED') {
      const activeLinked = accountRows.filter(account => account.metadata?.customer_id === customer.customer_id && account.status === 'ACTIVE');
      if (activeLinked.length) reasons.push(`SUSPENDED_CUSTOMER_HAS_ACTIVE_ACCOUNT:${customer.customer_id}`);
    }
  }

  for (const id of assessmentMap.keys()) {
    if (!monitorable.some(customer => customer.customer_id === id)) reasons.push(`UNEXPECTED_MONITORING_ASSESSMENT:${id}`);
  }

  const body = {
    schema: 'g-bank-monitoring-fleet-audit/v2',
    state: reasons.length ? 'BLOCK' : 'PASS',
    policy_sha256: policy.policy_sha256,
    policy_epoch: policy.epoch,
    monitorable_customer_count: monitorable.length,
    assessment_count: assessments.length,
    clear_customer_count: clearCount,
    review_required_customer_count: reviewCount,
    suspended_customer_count: suspendedCount,
    reasons: reasons.sort(),
    audited_at: new Date(now).toISOString(),
    regulatory_determination_made: false,
    external_report_submitted: false,
    permits_value_movement_by_itself: false,
  };
  return Object.freeze({ ...body, audit_sha256: sha256(canonicalJson(body)) });
}

module.exports = { auditMonitoringFleet, verifyAssessment };
