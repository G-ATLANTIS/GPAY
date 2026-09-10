'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { assessCustomerActivityFromLedger } = require('./transaction-activity-source');
const { ContinuousCustomerMonitoringService } = require('./continuous-customer-monitoring');
const { auditMonitoringFleet } = require('./monitoring-fleet-audit');

class MonitoringCycleCoordinator {
  constructor({ customers, accounts, ledger, customerControls, revocations, cases, policyStore }) {
    if (!customers || typeof customers.list !== 'function') throw new Error('monitoring_cycle_customers_required');
    if (!accounts || typeof accounts.list !== 'function') throw new Error('monitoring_cycle_accounts_required');
    if (!ledger || typeof ledger.verify !== 'function') throw new Error('monitoring_cycle_ledger_required');
    if (!customerControls || typeof customerControls.suspend !== 'function') throw new Error('monitoring_cycle_customer_controls_required');
    if (!revocations || typeof revocations.isRevoked !== 'function') throw new Error('monitoring_cycle_revocations_required');
    if (!cases || typeof cases.list !== 'function') throw new Error('monitoring_cycle_cases_required');
    if (!policyStore || typeof policyStore.active !== 'function' || typeof policyStore.verify !== 'function') throw new Error('monitoring_cycle_policy_store_required');
    this.customers = customers;
    this.accounts = accounts;
    this.ledger = ledger;
    this.customerControls = customerControls;
    this.revocations = revocations;
    this.cases = cases;
    this.policyStore = policyStore;
  }

  run({
    evidenceByCustomer,
    currency = 'EUR',
    window_start,
    window_end,
    rapid_interval_ms = 60000,
    enforce = true,
    now = Date.now(),
    max_assessment_age_ms = 15 * 60 * 1000,
  }) {
    if (!evidenceByCustomer || typeof evidenceByCustomer !== 'object') throw new Error('monitoring_cycle_evidence_map_required');
    const policyStoreProof = this.policyStore.verify();
    const policy = this.policyStore.active({ now });
    if (policyStoreProof.latest_epoch < policy.epoch) throw new Error('monitoring_cycle_policy_store_inconsistent');
    const ledgerProof = this.ledger.verify();
    if (ledgerProof.verified !== true) throw new Error('monitoring_cycle_ledger_not_verified');

    const monitorable = this.customers.list()
      .filter(customer => ['ACTIVE', 'SUSPENDED'].includes(customer.status))
      .sort((a, b) => a.customer_id.localeCompare(b.customer_id));
    const finalAssessments = [];
    const enforcementProofs = [];
    const sourceRoots = [];

    for (const customer of monitorable) {
      const monitoringEvidence = evidenceByCustomer[customer.customer_id];
      if (!monitoringEvidence) throw new Error(`monitoring_cycle_evidence_missing:${customer.customer_id}`);
      const activity = assessCustomerActivityFromLedger({
        customer_id: customer.customer_id,
        accounts: this.accounts,
        ledger: this.ledger,
        currency,
        window_start,
        window_end,
        rapid_interval_ms,
        policy: policy.transaction,
        now,
      });
      sourceRoots.push(Object.freeze({
        customer_id: customer.customer_id,
        transaction_source_root_sha256: activity.source.source_root_sha256,
        transaction_assessment_sha256: activity.assessment.assessment_sha256,
      }));

      const service = new ContinuousCustomerMonitoringService({
        customers: this.customers,
        customerControls: this.customerControls,
        revocations: this.revocations,
        cases: this.cases,
        monitoringPolicy: policy,
      });
      let assessment = service.assess({
        customer_id: customer.customer_id,
        monitoringEvidence,
        transactionAssessment: activity.assessment,
        now,
      });

      if (enforce) {
        const enforcement = service.enforce(assessment, { now });
        enforcementProofs.push(enforcement);
        // Enforcement may alter customer/account/case state. Re-assess against that final state
        // so the fleet audit cannot accidentally certify the pre-enforcement customer record.
        assessment = service.assess({
          customer_id: customer.customer_id,
          monitoringEvidence,
          transactionAssessment: activity.assessment,
          now,
        });
      }
      finalAssessments.push(assessment);
    }

    const fleetAudit = auditMonitoringFleet({
      customers: this.customers,
      accounts: this.accounts,
      assessments: finalAssessments,
      monitoringPolicy: policy,
      now,
      max_assessment_age_ms,
    });

    const body = {
      schema: 'g-bank-continuous-monitoring-cycle/v2',
      state: fleetAudit.state === 'PASS' ? 'PASS' : 'BLOCK',
      policy_sha256: policy.policy_sha256,
      policy_epoch: policy.epoch,
      policy_store_root_sha256: policyStoreProof.policy_root_sha256,
      ledger_head_sha256: ledgerProof.head_sha256,
      ledger_record_count: ledgerProof.record_count,
      customer_count: monitorable.length,
      assessment_sha256s: finalAssessments.map(item => item.assessment_sha256).sort(),
      enforcement_sha256s: enforcementProofs.map(item => item.enforcement_sha256).sort(),
      transaction_source_roots: sourceRoots.sort((a, b) => a.customer_id.localeCompare(b.customer_id)),
      fleet_audit_sha256: fleetAudit.audit_sha256,
      enforcement_enabled: enforce === true,
      automatic_reactivation_performed: false,
      regulatory_determination_made: false,
      external_report_submitted: false,
      external_payment_action_performed: false,
      value_moved: false,
      completed_at: new Date(now).toISOString(),
    };
    return Object.freeze({
      cycle: Object.freeze({ ...body, cycle_sha256: sha256(canonicalJson(body)) }),
      assessments: Object.freeze(finalAssessments),
      enforcements: Object.freeze(enforcementProofs),
      fleetAudit,
    });
  }
}

module.exports = { MonitoringCycleCoordinator };
