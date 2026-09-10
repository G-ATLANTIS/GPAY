'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function positive(name, value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error(`${name}_invalid`);
  return n;
}

function createMonitoringPolicy({
  policy_id = 'G_BANK_CONTINUOUS_MONITORING',
  epoch,
  effective_from,
  max_kyc_age_ms,
  max_screen_age_ms,
  transaction,
  case_review_sla_ms,
}) {
  const id = String(policy_id || '').toUpperCase();
  if (!/^[A-Z0-9_:-]{3,128}$/.test(id)) throw new Error('monitoring_policy_id_invalid');
  const ep = Number(epoch);
  if (!Number.isSafeInteger(ep) || ep <= 0) throw new Error('monitoring_policy_epoch_invalid');
  const effective = Date.parse(effective_from);
  if (!Number.isFinite(effective)) throw new Error('monitoring_policy_effective_from_invalid');
  if (!transaction || typeof transaction !== 'object') throw new Error('monitoring_policy_transaction_required');
  if (!case_review_sla_ms || typeof case_review_sla_ms !== 'object') throw new Error('monitoring_policy_case_sla_required');

  const tx = {
    review_single_minor: positive('review_single_minor', transaction.review_single_minor),
    suspend_single_minor: positive('suspend_single_minor', transaction.suspend_single_minor),
    review_window_outbound_minor: positive('review_window_outbound_minor', transaction.review_window_outbound_minor),
    suspend_window_outbound_minor: positive('suspend_window_outbound_minor', transaction.suspend_window_outbound_minor),
    review_transaction_count: positive('review_transaction_count', transaction.review_transaction_count),
    review_new_counterparty_count: positive('review_new_counterparty_count', transaction.review_new_counterparty_count),
    review_rapid_sequence_count: positive('review_rapid_sequence_count', transaction.review_rapid_sequence_count),
    suspend_rapid_sequence_count: positive('suspend_rapid_sequence_count', transaction.suspend_rapid_sequence_count),
    review_return_or_recall_count: positive('review_return_or_recall_count', transaction.review_return_or_recall_count),
  };
  if (tx.suspend_single_minor < tx.review_single_minor) throw new Error('monitoring_policy_single_threshold_order_invalid');
  if (tx.suspend_window_outbound_minor < tx.review_window_outbound_minor) throw new Error('monitoring_policy_window_threshold_order_invalid');
  if (tx.suspend_rapid_sequence_count < tx.review_rapid_sequence_count) throw new Error('monitoring_policy_rapid_threshold_order_invalid');

  const sla = {
    LOW: positive('case_sla_low', case_review_sla_ms.LOW),
    MEDIUM: positive('case_sla_medium', case_review_sla_ms.MEDIUM),
    HIGH: positive('case_sla_high', case_review_sla_ms.HIGH),
    CRITICAL: positive('case_sla_critical', case_review_sla_ms.CRITICAL),
  };
  if (!(sla.CRITICAL <= sla.HIGH && sla.HIGH <= sla.MEDIUM && sla.MEDIUM <= sla.LOW)) {
    throw new Error('monitoring_policy_case_sla_order_invalid');
  }

  const body = {
    schema: 'g-bank-continuous-monitoring-policy/v2',
    policy_id: id,
    epoch: ep,
    effective_from: new Date(effective).toISOString(),
    max_kyc_age_ms: positive('max_kyc_age_ms', max_kyc_age_ms),
    max_screen_age_ms: positive('max_screen_age_ms', max_screen_age_ms),
    transaction: tx,
    case_review_sla_ms: sla,
  };
  return Object.freeze({ ...body, policy_sha256: sha256(canonicalJson(body)) });
}

function verifyMonitoringPolicy(policy, { now = Date.now() } = {}) {
  if (!policy || policy.schema !== 'g-bank-continuous-monitoring-policy/v2') throw new Error('monitoring_policy_required');
  const supplied = String(policy.policy_sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) throw new Error('monitoring_policy_hash_invalid');
  const { policy_sha256, ...body } = policy;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('monitoring_policy_hash_mismatch');
  const effective = Date.parse(policy.effective_from);
  if (!Number.isFinite(effective) || effective > now + 30000) throw new Error('monitoring_policy_not_effective');
  return policy;
}

module.exports = { createMonitoringPolicy, verifyMonitoringPolicy };
