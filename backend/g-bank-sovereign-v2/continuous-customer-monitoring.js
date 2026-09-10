'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { verifyMonitoringEvidence } = require('./monitoring-evidence');
const { verifyTransactionAssessment } = require('./transaction-monitoring');

function rank(state) {
  return { CLEAR: 0, REVIEW_REQUIRED: 1, SUSPEND_REQUIRED: 2 }[state] ?? -1;
}

function raise(current, next) {
  return rank(next) > rank(current) ? next : current;
}

class ContinuousCustomerMonitoringService {
  constructor({ customers, customerControls, revocations, cases }) {
    if (!customers || typeof customers.get !== 'function') throw new Error('customer_registry_required');
    if (!customerControls || typeof customerControls.suspend !== 'function') throw new Error('customer_control_service_required');
    if (!revocations || typeof revocations.isRevoked !== 'function') throw new Error('evidence_revocation_store_required');
    if (!cases || typeof cases.open !== 'function' || typeof cases.list !== 'function') throw new Error('monitoring_case_store_required');
    this.customers = customers;
    this.controls = customerControls;
    this.revocations = revocations;
    this.cases = cases;
  }

  assess({ customer_id, monitoringEvidence, transactionAssessment = null, now = Date.now() }) {
    const customer = this.customers.get(customer_id);
    if (!['ACTIVE', 'SUSPENDED'].includes(customer.status)) throw new Error('customer_not_monitorable');

    let state = 'CLEAR';
    const reasons = [];
    let monitoringProof = null;

    try {
      monitoringProof = verifyMonitoringEvidence(monitoringEvidence, {
        subject_binding_sha256: customer.subject_binding_sha256,
        now,
      });
      const evidenceHashes = [
        monitoringProof.kyc_evidence_sha256,
        monitoringProof.sanctions_evidence_sha256,
        monitoringProof.pep_evidence_sha256,
      ];
      if (evidenceHashes.some(hash => this.revocations.isRevoked(hash))) {
        state = raise(state, 'SUSPEND_REQUIRED');
        reasons.push('MONITORING_EVIDENCE_REVOKED');
      }
    } catch (err) {
      state = raise(state, 'SUSPEND_REQUIRED');
      reasons.push(`MONITORING_EVIDENCE_INVALID:${String(err.message || 'unknown').slice(0, 160)}`);
    }

    let txHash = null;
    if (transactionAssessment) {
      const tx = verifyTransactionAssessment(transactionAssessment);
      if (tx.customer_id !== customer.customer_id) throw new Error('transaction_monitoring_customer_mismatch');
      txHash = tx.assessment_sha256;
      if (tx.state === 'SUSPEND_REQUIRED') {
        state = raise(state, 'SUSPEND_REQUIRED');
        reasons.push('TRANSACTION_MONITOR_SUSPEND_REQUIRED');
      } else if (tx.state === 'REVIEW_REQUIRED') {
        state = raise(state, 'REVIEW_REQUIRED');
        reasons.push('TRANSACTION_MONITOR_REVIEW_REQUIRED');
      }
    }

    const openCases = this.cases.list({ customer_id: customer.customer_id })
      .filter(item => ['OPEN', 'UNDER_REVIEW', 'ESCALATED'].includes(item.status));
    if (openCases.some(item => item.severity === 'CRITICAL')) {
      state = raise(state, 'SUSPEND_REQUIRED');
      reasons.push('CRITICAL_MONITORING_CASE_OPEN');
    } else if (openCases.some(item => ['HIGH', 'MEDIUM'].includes(item.severity))) {
      state = raise(state, 'REVIEW_REQUIRED');
      reasons.push('MONITORING_CASE_OPEN');
    }

    const body = {
      schema: 'g-bank-continuous-customer-monitoring-assessment/v2',
      state,
      customer_id: customer.customer_id,
      customer_status: customer.status,
      customer_record_sha256: customer.record_sha256,
      monitoring_proof_sha256: monitoringProof?.proof_sha256 || null,
      transaction_assessment_sha256: txHash,
      open_case_ids: openCases.map(item => item.case_id).sort(),
      reasons: [...new Set(reasons)].sort(),
      assessed_at: new Date(now).toISOString(),
      regulatory_suspicion_determined: false,
      external_report_submitted: false,
      reactivation_performed: false,
      permits_value_movement: false,
    };
    return Object.freeze({ ...body, assessment_sha256: sha256(canonicalJson(body)) });
  }

  enforce(assessment, { now = Date.now() } = {}) {
    if (!assessment || assessment.schema !== 'g-bank-continuous-customer-monitoring-assessment/v2') throw new Error('continuous_monitoring_assessment_required');
    const supplied = String(assessment.assessment_sha256 || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(supplied)) throw new Error('continuous_monitoring_assessment_hash_invalid');
    const { assessment_sha256, ...body } = assessment;
    if (sha256(canonicalJson(body)) !== supplied) throw new Error('continuous_monitoring_assessment_hash_mismatch');

    const customer = this.customers.get(assessment.customer_id);
    if (customer.record_sha256 !== assessment.customer_record_sha256) throw new Error('continuous_monitoring_customer_state_changed_reassess_required');

    let caseRecord = null;
    if (assessment.state !== 'CLEAR') {
      const caseId = `GCASE:MON:${assessment.assessment_sha256.slice(0, 32)}`;
      caseRecord = this.cases.list({ customer_id: customer.customer_id }).find(item => item.case_id === caseId) || null;
      if (!caseRecord) {
        caseRecord = this.cases.open({
          case_id: caseId,
          customer_id: customer.customer_id,
          signal_sha256: assessment.assessment_sha256,
          severity: assessment.state === 'SUSPEND_REQUIRED' ? 'CRITICAL' : 'MEDIUM',
          reason_code: assessment.state,
          now,
        });
      }
    }

    let suspension = null;
    if (assessment.state === 'SUSPEND_REQUIRED') {
      if (customer.status === 'ACTIVE') {
        suspension = this.controls.suspend({
          customer_id: customer.customer_id,
          evidence_sha256: assessment.assessment_sha256,
          reason: 'CONTINUOUS_MONITORING_FAIL_CLOSED',
          now,
        });
      } else if (customer.status !== 'SUSPENDED') {
        throw new Error('continuous_monitoring_customer_not_suspendable');
      }
    }

    const resultBody = {
      schema: 'g-bank-continuous-monitoring-enforcement/v2',
      customer_id: customer.customer_id,
      assessment_sha256: assessment.assessment_sha256,
      assessment_state: assessment.state,
      monitoring_case_id: caseRecord?.case_id || null,
      customer_suspension_performed: Boolean(suspension),
      automatic_reactivation_performed: false,
      external_action_performed: false,
      value_moved: false,
      enforced_at: new Date(now).toISOString(),
    };
    return Object.freeze({ ...resultBody, enforcement_sha256: sha256(canonicalJson(resultBody)) });
  }
}

module.exports = { ContinuousCustomerMonitoringService };
