'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { withAccountOperationLock } = require('./account-operation-lock');

function hash64(name, value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}_invalid`);
  return hash;
}

class CustomerControlService {
  constructor({ customers, accounts }) {
    if (!customers || typeof customers.get !== 'function' || typeof customers.transition !== 'function') throw new Error('customer_registry_required');
    if (!accounts || typeof accounts.list !== 'function' || typeof accounts.transitionStatus !== 'function') throw new Error('account_registry_required');
    this.customers = customers;
    this.accounts = accounts;
  }

  linkedAccounts(customerId) {
    return this.accounts.list({ type: 'CUSTOMER' }).filter(account => account.metadata?.customer_id === customerId);
  }

  suspend({ customer_id, evidence_sha256, reason = 'CUSTOMER_CONTROL_SUSPENSION', now = Date.now() }) {
    const evidence = hash64('customer_control_evidence_sha256', evidence_sha256);
    return withAccountOperationLock(this.accounts, () => {
      let customer = this.customers.get(customer_id);
      if (!['ACTIVE', 'SUSPENDED'].includes(customer.status)) throw new Error('customer_not_suspendable');
      const linked = this.linkedAccounts(customer.customer_id);
      const suspendedAccounts = [];
      for (const account of linked) {
        if (account.status === 'ACTIVE') {
          const updated = this.accounts.transitionStatus({
            account_id: account.account_id,
            expected_status: 'ACTIVE',
            to_status: 'SUSPENDED',
            evidence_sha256: evidence,
            reason,
            now,
          });
          suspendedAccounts.push(updated.account_id);
        } else if (account.status !== 'SUSPENDED' && account.status !== 'CLOSED') {
          throw new Error('linked_account_state_invalid');
        }
      }
      if (customer.status === 'ACTIVE') {
        customer = this.customers.transition({
          customer_id: customer.customer_id,
          expected_status: 'ACTIVE',
          to_status: 'SUSPENDED',
          decision_evidence_sha256: evidence,
          reason,
          now,
        });
      }
      const stillActive = this.linkedAccounts(customer.customer_id).filter(account => account.status === 'ACTIVE');
      if (stillActive.length) throw new Error('customer_suspension_incomplete_active_account_remains');
      const body = {
        schema: 'g-bank-customer-control-proof/v2',
        action: 'SUSPEND',
        customer_id: customer.customer_id,
        customer_record_sha256: customer.record_sha256,
        evidence_sha256: evidence,
        linked_account_count: linked.length,
        newly_suspended_account_ids: suspendedAccounts.sort(),
        resulting_customer_status: customer.status,
        external_action_performed: false,
        value_moved: false,
        controlled_at: new Date(now).toISOString(),
      };
      return Object.freeze({ customer, proof: Object.freeze({ ...body, proof_sha256: sha256(canonicalJson(body)) }) });
    });
  }

  reactivate({ customer_id, evidence_sha256, reason = 'CUSTOMER_CONTROL_REACTIVATION', now = Date.now() }) {
    const evidence = hash64('customer_control_evidence_sha256', evidence_sha256);
    return withAccountOperationLock(this.accounts, () => {
      let customer = this.customers.get(customer_id);
      if (!['SUSPENDED', 'ACTIVE'].includes(customer.status)) throw new Error('customer_not_reactivatable');
      if (customer.status === 'SUSPENDED') {
        customer = this.customers.transition({
          customer_id: customer.customer_id,
          expected_status: 'SUSPENDED',
          to_status: 'ACTIVE',
          decision_evidence_sha256: evidence,
          reason,
          now,
        });
      }
      const linked = this.linkedAccounts(customer.customer_id);
      const reactivatedAccounts = [];
      for (const account of linked) {
        if (account.status === 'SUSPENDED') {
          const updated = this.accounts.transitionStatus({
            account_id: account.account_id,
            expected_status: 'SUSPENDED',
            to_status: 'ACTIVE',
            evidence_sha256: evidence,
            reason,
            now,
          });
          reactivatedAccounts.push(updated.account_id);
        } else if (account.status !== 'ACTIVE' && account.status !== 'CLOSED') {
          throw new Error('linked_account_state_invalid');
        }
      }
      const body = {
        schema: 'g-bank-customer-control-proof/v2',
        action: 'REACTIVATE',
        customer_id: customer.customer_id,
        customer_record_sha256: customer.record_sha256,
        evidence_sha256: evidence,
        linked_account_count: linked.length,
        newly_reactivated_account_ids: reactivatedAccounts.sort(),
        resulting_customer_status: customer.status,
        external_action_performed: false,
        value_moved: false,
        controlled_at: new Date(now).toISOString(),
      };
      return Object.freeze({ customer, proof: Object.freeze({ ...body, proof_sha256: sha256(canonicalJson(body)) }) });
    });
  }

  close({ customer_id, evidence_sha256, reason = 'CUSTOMER_RELATIONSHIP_CLOSED', now = Date.now() }) {
    const evidence = hash64('customer_control_evidence_sha256', evidence_sha256);
    return withAccountOperationLock(this.accounts, () => {
      const customer = this.customers.get(customer_id);
      if (customer.status !== 'SUSPENDED') throw new Error('customer_must_be_suspended_before_close');
      const linked = this.linkedAccounts(customer.customer_id);
      const notClosed = linked.filter(account => account.status !== 'CLOSED');
      if (notClosed.length) throw new Error('customer_close_requires_all_accounts_closed');
      const closed = this.customers.transition({
        customer_id: customer.customer_id,
        expected_status: 'SUSPENDED',
        to_status: 'CLOSED',
        decision_evidence_sha256: evidence,
        reason,
        now,
      });
      const body = {
        schema: 'g-bank-customer-control-proof/v2',
        action: 'CLOSE',
        customer_id: closed.customer_id,
        customer_record_sha256: closed.record_sha256,
        evidence_sha256: evidence,
        linked_account_count: linked.length,
        resulting_customer_status: closed.status,
        external_action_performed: false,
        value_moved: false,
        controlled_at: new Date(now).toISOString(),
      };
      return Object.freeze({ customer: closed, proof: Object.freeze({ ...body, proof_sha256: sha256(canonicalJson(body)) }) });
    });
  }
}

module.exports = { CustomerControlService };
