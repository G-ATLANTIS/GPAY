'use strict';

const { withAccountOperationLock } = require('./account-operation-lock');

function hash64(name, value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}_invalid`);
  return hash;
}

class AccountLifecycle {
  constructor({ accounts, ledger, inboundStore }) {
    if (!accounts || typeof accounts.get !== 'function' || typeof accounts.transitionStatus !== 'function') throw new Error('account_registry_required');
    if (!ledger || typeof ledger.balance !== 'function' || typeof ledger.verify !== 'function') throw new Error('sovereign_ledger_required');
    if (!inboundStore || typeof inboundStore.currentAll !== 'function' || typeof inboundStore.verify !== 'function') throw new Error('inbound_store_required');
    this.accounts = accounts;
    this.ledger = ledger;
    this.inboundStore = inboundStore;
  }

  suspend({ account_id, evidence_sha256, reason = 'OPERATOR_SUSPENSION', now = Date.now() }) {
    return withAccountOperationLock(this.accounts, () => {
      const account = this.accounts.get(account_id);
      if (account.type !== 'CUSTOMER') throw new Error('customer_account_required');
      return this.accounts.transitionStatus({
        account_id,
        expected_status: 'ACTIVE',
        to_status: 'SUSPENDED',
        evidence_sha256: hash64('account_lifecycle_evidence_sha256', evidence_sha256),
        reason,
        now,
      });
    });
  }

  reactivate({ account_id, evidence_sha256, reason = 'OPERATOR_REACTIVATION', now = Date.now() }) {
    return withAccountOperationLock(this.accounts, () => {
      const account = this.accounts.get(account_id);
      if (account.type !== 'CUSTOMER') throw new Error('customer_account_required');
      return this.accounts.transitionStatus({
        account_id,
        expected_status: 'SUSPENDED',
        to_status: 'ACTIVE',
        evidence_sha256: hash64('account_lifecycle_evidence_sha256', evidence_sha256),
        reason,
        now,
      });
    });
  }

  close({ account_id, evidence_sha256, reason = 'CUSTOMER_ACCOUNT_CLOSED', now = Date.now() }) {
    return withAccountOperationLock(this.accounts, () => {
      const account = this.accounts.get(account_id);
      if (account.type !== 'CUSTOMER') throw new Error('customer_account_required');
      if (account.status !== 'SUSPENDED') throw new Error('account_must_be_suspended_before_close');
      const verification = this.ledger.verify();
      if (verification.verified !== true) throw new Error('ledger_not_verified');
      const inboundProof = this.inboundStore.verify();
      if (inboundProof.verified !== true) throw new Error('inbound_store_not_verified');
      const unresolved = this.inboundStore.currentAll().filter(row =>
        row.target_account_id === account.account_id && ['CLAIMED', 'PENDING'].includes(row.state)
      );
      if (unresolved.length) throw new Error('account_close_blocked_by_pending_inbound');
      const balance = this.ledger.balance(account.account_id, account.currency);
      if (balance !== 0) throw new Error('account_close_requires_zero_balance');
      return this.accounts.transitionStatus({
        account_id,
        expected_status: 'SUSPENDED',
        to_status: 'CLOSED',
        evidence_sha256: hash64('account_lifecycle_evidence_sha256', evidence_sha256),
        reason,
        now,
      });
    });
  }
}

module.exports = { AccountLifecycle };
