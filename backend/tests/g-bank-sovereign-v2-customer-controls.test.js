'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { CustomerRegistry } = require('../g-bank-sovereign-v2/customer-registry');
const { AccountRegistry } = require('../g-bank-sovereign-v2/accounts');
const { CustomerControlService } = require('../g-bank-sovereign-v2/customer-controls');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T08:30:00.000Z');

function setup() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-customer-control-v2-'));
  const customers = new CustomerRegistry(path.join(root, 'customers.jsonl'));
  const accounts = new AccountRegistry(path.join(root, 'accounts.json'));
  const customer = customers.create({
    customer_id: 'G:CUSTOMER-SUBJECT:CONTROL',
    subject_binding_sha256: H('1'),
    jurisdiction: 'NL',
    now: NOW - 10000,
  });
  customers.transition({ customer_id: customer.customer_id, expected_status: 'PROSPECT', to_status: 'REVIEW', decision_evidence_sha256: H('2'), now: NOW - 9000 });
  customers.transition({ customer_id: customer.customer_id, expected_status: 'REVIEW', to_status: 'ACTIVE', decision_evidence_sha256: H('3'), now: NOW - 8000 });
  for (const [id, iban] of [['G:CUSTOMER:CTRL-A', null], ['G:CUSTOMER:CTRL-B', null]]) {
    accounts.register({
      account_id: id,
      type: 'CUSTOMER',
      currency: 'EUR',
      iban,
      owner_binding_sha256: H('1'),
      metadata: { customer_id: customer.customer_id },
    });
  }
  return { customers, accounts, controls: new CustomerControlService({ customers, accounts }), customerId: customer.customer_id };
}

(() => {
  const s = setup();
  const suspended = s.controls.suspend({ customer_id: s.customerId, evidence_sha256: H('4'), now: NOW });
  assert.equal(suspended.customer.status, 'SUSPENDED');
  assert.equal(s.accounts.get('G:CUSTOMER:CTRL-A').status, 'SUSPENDED');
  assert.equal(s.accounts.get('G:CUSTOMER:CTRL-B').status, 'SUSPENDED');
  assert.equal(suspended.proof.external_action_performed, false);
  assert.equal(suspended.proof.value_moved, false);

  const duplicateSuspend = s.controls.suspend({ customer_id: s.customerId, evidence_sha256: H('4'), now: NOW + 100 });
  assert.equal(duplicateSuspend.customer.status, 'SUSPENDED');
  assert.deepEqual(duplicateSuspend.proof.newly_suspended_account_ids, []);

  const reactivated = s.controls.reactivate({ customer_id: s.customerId, evidence_sha256: H('5'), now: NOW + 200 });
  assert.equal(reactivated.customer.status, 'ACTIVE');
  assert.equal(s.accounts.get('G:CUSTOMER:CTRL-A').status, 'ACTIVE');
  assert.equal(s.accounts.get('G:CUSTOMER:CTRL-B').status, 'ACTIVE');

  s.controls.suspend({ customer_id: s.customerId, evidence_sha256: H('6'), now: NOW + 300 });
  assert.throws(() => s.controls.close({ customer_id: s.customerId, evidence_sha256: H('7'), now: NOW + 400 }), /all_accounts_closed/);

  s.accounts.transitionStatus({ account_id: 'G:CUSTOMER:CTRL-A', expected_status: 'SUSPENDED', to_status: 'CLOSED', evidence_sha256: H('8'), now: NOW + 500 });
  s.accounts.transitionStatus({ account_id: 'G:CUSTOMER:CTRL-B', expected_status: 'SUSPENDED', to_status: 'CLOSED', evidence_sha256: H('8'), now: NOW + 500 });
  const closed = s.controls.close({ customer_id: s.customerId, evidence_sha256: H('9'), now: NOW + 600 });
  assert.equal(closed.customer.status, 'CLOSED');
  assert.equal(closed.proof.value_moved, false);
  assert.throws(() => s.controls.reactivate({ customer_id: s.customerId, evidence_sha256: H('a'), now: NOW + 700 }), /not_reactivatable/);
})();

(() => {
  const s = setup();
  s.accounts.transitionStatus({ account_id: 'G:CUSTOMER:CTRL-A', expected_status: 'ACTIVE', to_status: 'SUSPENDED', evidence_sha256: H('b'), now: NOW });
  s.accounts.transitionStatus({ account_id: 'G:CUSTOMER:CTRL-B', expected_status: 'ACTIVE', to_status: 'SUSPENDED', evidence_sha256: H('b'), now: NOW });
  assert.equal(s.customers.get(s.customerId).status, 'ACTIVE');
  const recovered = s.controls.suspend({ customer_id: s.customerId, evidence_sha256: H('c'), now: NOW + 100 });
  assert.equal(recovered.customer.status, 'SUSPENDED');
  assert.equal(s.accounts.list({ type: 'CUSTOMER', status: 'ACTIVE' }).length, 0);
})();

(() => {
  const s = setup();
  s.controls.suspend({ customer_id: s.customerId, evidence_sha256: H('d'), now: NOW });
  s.customers.transition({ customer_id: s.customerId, expected_status: 'SUSPENDED', to_status: 'ACTIVE', decision_evidence_sha256: H('e'), now: NOW + 50 });
  assert.equal(s.accounts.get('G:CUSTOMER:CTRL-A').status, 'SUSPENDED');
  const recovered = s.controls.reactivate({ customer_id: s.customerId, evidence_sha256: H('f'), now: NOW + 100 });
  assert.equal(recovered.customer.status, 'ACTIVE');
  assert.equal(s.accounts.get('G:CUSTOMER:CTRL-A').status, 'ACTIVE');
  assert.equal(s.accounts.get('G:CUSTOMER:CTRL-B').status, 'ACTIVE');
})();

console.log('G-BANK sovereign v2 customer controls tests: PASS');
