'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { verifyMonitoringPolicy } = require('./monitoring-policy');

function assessMonitoringCaseSla({ cases, policy, now = Date.now() }) {
  const verifiedPolicy = verifyMonitoringPolicy(policy, { now });
  if (!Array.isArray(cases)) throw new Error('monitoring_case_sla_cases_required');
  const open = cases.filter(item => ['OPEN', 'UNDER_REVIEW', 'ESCALATED'].includes(item.status));
  const overdue = [];
  for (const item of open) {
    const opened = Date.parse(item.opened_at);
    if (!Number.isFinite(opened)) throw new Error('monitoring_case_opened_at_invalid');
    const severity = String(item.severity || '').toUpperCase();
    const sla = verifiedPolicy.case_review_sla_ms[severity];
    if (!Number.isSafeInteger(sla) || sla <= 0) throw new Error('monitoring_case_sla_missing');
    const due = opened + sla;
    if (now > due) {
      overdue.push(Object.freeze({
        case_id: item.case_id,
        severity,
        opened_at: new Date(opened).toISOString(),
        due_at: new Date(due).toISOString(),
        overdue_ms: now - due,
      }));
    }
  }
  overdue.sort((a, b) => a.case_id.localeCompare(b.case_id));
  const criticalOverdue = overdue.some(item => ['CRITICAL', 'HIGH'].includes(item.severity));
  const body = {
    schema: 'g-bank-monitoring-case-sla-assessment/v2',
    state: criticalOverdue ? 'SUSPEND_REQUIRED' : overdue.length ? 'REVIEW_REQUIRED' : 'PASS',
    policy_sha256: verifiedPolicy.policy_sha256,
    policy_epoch: verifiedPolicy.epoch,
    open_case_count: open.length,
    overdue_cases: overdue,
    assessed_at: new Date(now).toISOString(),
    regulatory_determination_made: false,
    external_action_performed: false,
    permits_value_movement: false,
  };
  return Object.freeze({ ...body, assessment_sha256: sha256(canonicalJson(body)) });
}

module.exports = { assessMonitoringCaseSla };
