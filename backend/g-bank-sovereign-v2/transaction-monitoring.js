'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function safeNonNegative(name, value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${name}_invalid`);
  return n;
}

function positiveLimit(name, value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error(`${name}_invalid`);
  return n;
}

function assessTransactionActivity({
  customer_id,
  currency,
  window_start,
  window_end,
  transaction_count,
  total_inbound_minor,
  total_outbound_minor,
  max_single_transaction_minor,
  distinct_counterparty_count = 0,
  new_counterparty_count = 0,
  rapid_sequence_count = 0,
  return_or_recall_count = 0,
  source_root_sha256,
  policy,
  now = Date.now(),
}) {
  const customer = String(customer_id || '').trim();
  if (!customer) throw new Error('transaction_monitor_customer_id_invalid');
  const ccy = String(currency || '').toUpperCase();
  if (!/^[A-Z]{3}$/.test(ccy)) throw new Error('transaction_monitor_currency_invalid');
  const start = Date.parse(window_start);
  const end = Date.parse(window_end);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start || end > now + 30000) throw new Error('transaction_monitor_window_invalid');
  const sourceRoot = String(source_root_sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(sourceRoot)) throw new Error('transaction_monitor_source_root_invalid');
  if (!policy || typeof policy !== 'object') throw new Error('transaction_monitor_policy_required');

  const metrics = {
    transaction_count: safeNonNegative('transaction_count', transaction_count),
    total_inbound_minor: safeNonNegative('total_inbound_minor', total_inbound_minor),
    total_outbound_minor: safeNonNegative('total_outbound_minor', total_outbound_minor),
    max_single_transaction_minor: safeNonNegative('max_single_transaction_minor', max_single_transaction_minor),
    distinct_counterparty_count: safeNonNegative('distinct_counterparty_count', distinct_counterparty_count),
    new_counterparty_count: safeNonNegative('new_counterparty_count', new_counterparty_count),
    rapid_sequence_count: safeNonNegative('rapid_sequence_count', rapid_sequence_count),
    return_or_recall_count: safeNonNegative('return_or_recall_count', return_or_recall_count),
  };

  const limits = {
    review_single_minor: positiveLimit('review_single_minor', policy.review_single_minor),
    suspend_single_minor: positiveLimit('suspend_single_minor', policy.suspend_single_minor),
    review_window_outbound_minor: positiveLimit('review_window_outbound_minor', policy.review_window_outbound_minor),
    suspend_window_outbound_minor: positiveLimit('suspend_window_outbound_minor', policy.suspend_window_outbound_minor),
    review_transaction_count: positiveLimit('review_transaction_count', policy.review_transaction_count),
    review_new_counterparty_count: positiveLimit('review_new_counterparty_count', policy.review_new_counterparty_count),
    review_rapid_sequence_count: positiveLimit('review_rapid_sequence_count', policy.review_rapid_sequence_count),
    suspend_rapid_sequence_count: positiveLimit('suspend_rapid_sequence_count', policy.suspend_rapid_sequence_count),
    review_return_or_recall_count: positiveLimit('review_return_or_recall_count', policy.review_return_or_recall_count),
  };
  if (limits.suspend_single_minor < limits.review_single_minor) throw new Error('transaction_monitor_single_limits_invalid');
  if (limits.suspend_window_outbound_minor < limits.review_window_outbound_minor) throw new Error('transaction_monitor_window_limits_invalid');
  if (limits.suspend_rapid_sequence_count < limits.review_rapid_sequence_count) throw new Error('transaction_monitor_rapid_limits_invalid');

  const reasons = [];
  let state = 'CLEAR';
  const raise = next => {
    const rank = { CLEAR: 0, REVIEW_REQUIRED: 1, SUSPEND_REQUIRED: 2 };
    if (rank[next] > rank[state]) state = next;
  };

  if (metrics.max_single_transaction_minor >= limits.suspend_single_minor) {
    reasons.push('SINGLE_TRANSACTION_SUSPEND_THRESHOLD');
    raise('SUSPEND_REQUIRED');
  } else if (metrics.max_single_transaction_minor >= limits.review_single_minor) {
    reasons.push('SINGLE_TRANSACTION_REVIEW_THRESHOLD');
    raise('REVIEW_REQUIRED');
  }

  if (metrics.total_outbound_minor >= limits.suspend_window_outbound_minor) {
    reasons.push('OUTBOUND_WINDOW_SUSPEND_THRESHOLD');
    raise('SUSPEND_REQUIRED');
  } else if (metrics.total_outbound_minor >= limits.review_window_outbound_minor) {
    reasons.push('OUTBOUND_WINDOW_REVIEW_THRESHOLD');
    raise('REVIEW_REQUIRED');
  }

  if (metrics.rapid_sequence_count >= limits.suspend_rapid_sequence_count) {
    reasons.push('RAPID_SEQUENCE_SUSPEND_THRESHOLD');
    raise('SUSPEND_REQUIRED');
  } else if (metrics.rapid_sequence_count >= limits.review_rapid_sequence_count) {
    reasons.push('RAPID_SEQUENCE_REVIEW_THRESHOLD');
    raise('REVIEW_REQUIRED');
  }

  if (metrics.transaction_count >= limits.review_transaction_count) {
    reasons.push('TRANSACTION_COUNT_REVIEW_THRESHOLD');
    raise('REVIEW_REQUIRED');
  }
  if (metrics.new_counterparty_count >= limits.review_new_counterparty_count) {
    reasons.push('NEW_COUNTERPARTY_REVIEW_THRESHOLD');
    raise('REVIEW_REQUIRED');
  }
  if (metrics.return_or_recall_count >= limits.review_return_or_recall_count) {
    reasons.push('RETURN_RECALL_REVIEW_THRESHOLD');
    raise('REVIEW_REQUIRED');
  }

  const body = {
    schema: 'g-bank-transaction-monitoring-assessment/v2',
    state,
    customer_id: customer,
    currency: ccy,
    window_start: new Date(start).toISOString(),
    window_end: new Date(end).toISOString(),
    metrics,
    policy: limits,
    reasons: reasons.sort(),
    source_root_sha256: sourceRoot,
    assessed_at: new Date(now).toISOString(),
    regulatory_suspicion_determined: false,
    external_report_submitted: false,
    permits_value_movement: false,
  };
  return Object.freeze({ ...body, assessment_sha256: sha256(canonicalJson(body)) });
}

function verifyTransactionAssessment(assessment) {
  if (!assessment || assessment.schema !== 'g-bank-transaction-monitoring-assessment/v2') throw new Error('transaction_monitoring_assessment_required');
  const supplied = String(assessment.assessment_sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) throw new Error('transaction_monitoring_assessment_hash_invalid');
  const { assessment_sha256, ...body } = assessment;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('transaction_monitoring_assessment_hash_mismatch');
  if (!['CLEAR', 'REVIEW_REQUIRED', 'SUSPEND_REQUIRED'].includes(assessment.state)) throw new Error('transaction_monitoring_assessment_state_invalid');
  return assessment;
}

module.exports = { assessTransactionActivity, verifyTransactionAssessment };
