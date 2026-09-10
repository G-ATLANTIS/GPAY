'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { canonicalJson, sha256 } = require('../g-bank-sovereign-v2/canonical');
const { CustomerRegistry } = require('../g-bank-sovereign-v2/customer-registry');
const { CustomerOnboardingService, verifyCustomerOnboardingBundle } = require('../g-bank-sovereign-v2/customer-onboarding');
const { CustomerAccountProvisioner } = require('../g-bank-sovereign-v2/customer-account-provisioning');
const { AccountRegistry } = require('../g-bank-sovereign-v2/accounts');
const { snapshotState, verifyCheckpoint } = require('../g-bank-sovereign-v2/checkpoint');

const NOW = Date.parse('2026-09-10T08:00:00.000Z');
const H = c => c.repeat(64);

function hashed(body, field) {
  return Object.freeze({ ...body, [field]: sha256(canonicalJson(body)) });
}

function onboardingBundle(subject) {
  const identity = hashed({
    schema: 'g-bank-identity-verification-evidence/v2',
    result: 'VERIFIED',
    subject_binding_sha256: subject,
    provider: 'AUTHORIZED-TEST-IDENTITY',
    provider_receipt_sha256: H('a'),
    observed_at: new Date(NOW - 3000).toISOString(),
  }, 'evidence_sha256');
  const sanctions = hashed({
    schema: 'g-bank-customer-sanctions-evidence/v2',
    result: 'CLEAR',
    subject_binding_sha256: subject,
    provider: 'AUTHORIZED-TEST-SCREENING',
    provider_receipt_sha256: H('b'),
    observed_at: new Date(NOW - 2500).toISOString(),
  }, 'evidence_sha256');
  const pep = hashed({
    schema: 'g-bank-pep-assessment-evidence/v2',
    result: 'CLEAR',
    subject_binding_sha256: subject,
    provider: 'AUTHORIZED-TEST-SCREENING',
    provider_receipt_sha256: H('c'),
    observed_at: new Date(NOW - 2000).toISOString(),
  }, 'evidence_sha256');
  const decision = hashed({
    schema: 'g-bank-onboarding-operator-decision/v2',
    decision: 'APPROVE',
    risk_class: 'LOW',
    subject_binding_sha256: subject,
    operator_binding_sha256: H('d'),
    decided_at: new Date(NOW - 1000).toISOString(),
  }, 'decision_sha256');
  return hashed({
    schema: 'g-bank-customer-onboarding-bundle/v2',
    subject_binding_sha256: subject,
    identity_verification: identity,
    sanctions_screen: sanctions,
    pep_assessment: pep,
    operator_decision: decision,
  }, 'bundle_sha256');
}

function ibanEvidence(subject, iban) {
  return hashed({
    schema: 'g-bank-external-iban-assignment-evidence/v2',
    state: 'ASSIGNED',
    subject_binding_sha256: subject,
    iban,
    issuer: 'AUTHORIZED-TEST-IBAN-ISSUER',
    external_receipt_sha256: H('e'),
    assigned_at: new Date(NOW - 500).toISOString(),
  }, 'evidence_sha256');
}

(() => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-customer-v2-'));
  const customerPath = path.join(root, 'customers.jsonl');
  const accountPath = path.join(root, 'accounts.json');
  const customers = new CustomerRegistry(customerPath);
  const accounts = new AccountRegistry(accountPath);
  const onboarding = new CustomerOnboardingService({ customers });
  const provisioner = new CustomerAccountProvisioner({ customers, accounts });
  const subject = H('1');

  const prospect = customers.create({
    customer_id: 'G:CUSTOMER-SUBJECT:001',
    subject_binding_sha256: subject,
    customer_type: 'NATURAL_PERSON',
    jurisdiction: 'NL',
    now: NOW - 10000,
  });
  assert.equal(prospect.status, 'PROSPECT');
  assert.equal(customers.verify().verified, true);
  assert.equal('name' in prospect, false);
  assert.equal('date_of_birth' in prospect, false);

  assert.throws(() => provisioner.open({
    customer_id: prospect.customer_id,
    account_id: 'G:CUSTOMER:PREMATURE',
    currency: 'EUR',
    now: NOW,
  }), /customer_not_active/);

  const review = onboarding.startReview({ customer_id: prospect.customer_id, evidence_sha256: H('2'), now: NOW - 5000 });
  assert.equal(review.status, 'REVIEW');

  const bundle = onboardingBundle(subject);
  const proof = verifyCustomerOnboardingBundle(bundle, { subject_binding_sha256: subject, now: NOW });
  assert.equal(proof.technical_gate_only, true);
  assert.equal(proof.grants_regulatory_authorization, false);
  assert.match(proof.proof_sha256, /^[0-9a-f]{64}$/);

  const activated = onboarding.activate({ customer_id: prospect.customer_id, onboardingBundle: bundle, now: NOW });
  assert.equal(activated.customer.status, 'ACTIVE');
  assert.equal(activated.customer.decision_evidence_sha256, activated.onboarding_proof.proof_sha256);

  const internalOnly = provisioner.open({
    customer_id: prospect.customer_id,
    account_id: 'G:CUSTOMER:INTERNAL',
    currency: 'EUR',
    now: NOW,
  });
  assert.equal(internalOnly.account.iban, null);
  assert.equal(internalOnly.provisioning_proof.local_iban_issuance_performed, false);
  assert.equal(internalOnly.provisioning_proof.grants_iban_issuance_authority, false);

  assert.throws(() => provisioner.open({
    customer_id: prospect.customer_id,
    account_id: 'G:CUSTOMER:NO-EVIDENCE',
    currency: 'EUR',
    iban: 'NL02ABNA0123456789',
    now: NOW,
  }), /external_iban_assignment_evidence_required/);

  const assignment = ibanEvidence(subject, 'NL02ABNA0123456789');
  const externallyAssigned = provisioner.open({
    customer_id: prospect.customer_id,
    account_id: 'G:CUSTOMER:EXT-IBAN',
    currency: 'EUR',
    iban: 'NL02ABNA0123456789',
    ibanAssignmentEvidence: assignment,
    now: NOW,
  });
  assert.equal(externallyAssigned.account.iban, 'NL02ABNA0123456789');
  assert.equal(externallyAssigned.account.metadata.iban_source, 'VERIFIED_EXTERNAL_ASSIGNMENT');
  assert.equal(externallyAssigned.provisioning_proof.local_iban_issuance_performed, false);

  const tamperedAssignment = { ...assignment, iban: 'NL91ABNA0417164300' };
  assert.throws(() => provisioner.open({
    customer_id: prospect.customer_id,
    account_id: 'G:CUSTOMER:TAMPERED-IBAN',
    currency: 'EUR',
    iban: 'NL91ABNA0417164300',
    ibanAssignmentEvidence: tamperedAssignment,
    now: NOW,
  }), /hash_mismatch/);

  const tamperedBundle = { ...bundle, operator_decision: { ...bundle.operator_decision, risk_class: 'HIGH' } };
  assert.throws(() => verifyCustomerOnboardingBundle(tamperedBundle, { subject_binding_sha256: subject, now: NOW }), /hash_mismatch/);

  const rejectedSubject = H('3');
  customers.create({ customer_id: 'G:CUSTOMER-SUBJECT:REJECT', subject_binding_sha256: rejectedSubject, now: NOW - 5000 });
  onboarding.startReview({ customer_id: 'G:CUSTOMER-SUBJECT:REJECT', evidence_sha256: H('4'), now: NOW - 4000 });
  onboarding.reject({ customer_id: 'G:CUSTOMER-SUBJECT:REJECT', decision_evidence_sha256: H('5'), now: NOW });
  assert.throws(() => provisioner.open({
    customer_id: 'G:CUSTOMER-SUBJECT:REJECT',
    account_id: 'G:CUSTOMER:REJECTED',
    currency: 'EUR',
    now: NOW,
  }), /customer_not_active/);

  const rawRegistry = fs.readFileSync(customerPath, 'utf8');
  assert.equal(rawRegistry.includes('Alice'), false);
  assert.equal(rawRegistry.includes('date_of_birth'), false);

  const checkpoint = snapshotState({
    accountRegistryPath: accountPath,
    customerRegistryPath: customerPath,
    ledgerPath: path.join(root, 'ledger.jsonl'),
    receiptsPath: path.join(root, 'receipts.jsonl'),
    executionsDir: path.join(root, 'executions'),
    inboundStatePath: path.join(root, 'inbound.jsonl'),
    now: NOW,
  });
  assert.match(checkpoint.customer_registry_sha256, /^[0-9a-f]{64}$/);
  const checkpointVerification = verifyCheckpoint(checkpoint, {
    accountRegistryPath: accountPath,
    customerRegistryPath: customerPath,
    ledgerPath: path.join(root, 'ledger.jsonl'),
    receiptsPath: path.join(root, 'receipts.jsonl'),
    executionsDir: path.join(root, 'executions'),
    inboundStatePath: path.join(root, 'inbound.jsonl'),
  });
  assert.equal(checkpointVerification.verified, true);
  assert.equal(checkpointVerification.checks.customer_registry, true);

  console.log('G-BANK sovereign v2 customer onboarding tests: PASS');
})();
