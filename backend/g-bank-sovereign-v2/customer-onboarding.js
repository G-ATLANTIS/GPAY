'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function hash64(name, value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}_invalid`);
  return hash;
}

function fresh(name, value, now, maxAge) {
  const t = Date.parse(value);
  if (!Number.isFinite(t)) throw new Error(`${name}_time_invalid`);
  if (t > now + 30000 || now - t > maxAge) throw new Error(`${name}_stale`);
  return t;
}

function verifyHashedObject(name, value, hashField) {
  if (!value || typeof value !== 'object') throw new Error(`${name}_required`);
  const supplied = hash64(`${name}_${hashField}`, value[hashField]);
  const { [hashField]: omitted, ...body } = value;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error(`${name}_hash_mismatch`);
  return value;
}

function verifyCustomerOnboardingBundle(bundle, {
  subject_binding_sha256,
  now = Date.now(),
  max_identity_age_ms = 30 * 24 * 60 * 60 * 1000,
  max_screen_age_ms = 24 * 60 * 60 * 1000,
  max_decision_age_ms = 24 * 60 * 60 * 1000,
} = {}) {
  verifyHashedObject('customer_onboarding_bundle', bundle, 'bundle_sha256');
  if (bundle.schema !== 'g-bank-customer-onboarding-bundle/v2') throw new Error('customer_onboarding_bundle_schema_invalid');
  const subject = hash64('subject_binding_sha256', subject_binding_sha256);
  if (bundle.subject_binding_sha256 !== subject) throw new Error('customer_onboarding_subject_mismatch');

  const identity = verifyHashedObject('identity_verification', bundle.identity_verification, 'evidence_sha256');
  if (identity.result !== 'VERIFIED') throw new Error('identity_not_verified');
  if (identity.subject_binding_sha256 !== subject) throw new Error('identity_subject_mismatch');
  fresh('identity_verification', identity.observed_at, now, max_identity_age_ms);
  hash64('identity_provider_receipt_sha256', identity.provider_receipt_sha256);

  const sanctions = verifyHashedObject('customer_sanctions_screen', bundle.sanctions_screen, 'evidence_sha256');
  if (sanctions.result !== 'CLEAR') throw new Error('customer_sanctions_not_clear');
  if (sanctions.subject_binding_sha256 !== subject) throw new Error('customer_sanctions_subject_mismatch');
  fresh('customer_sanctions_screen', sanctions.observed_at, now, max_screen_age_ms);
  hash64('customer_sanctions_provider_receipt_sha256', sanctions.provider_receipt_sha256);

  const pep = verifyHashedObject('pep_assessment', bundle.pep_assessment, 'evidence_sha256');
  if (!['CLEAR', 'EDD_COMPLETE'].includes(pep.result)) throw new Error('pep_assessment_not_cleared');
  if (pep.subject_binding_sha256 !== subject) throw new Error('pep_subject_mismatch');
  fresh('pep_assessment', pep.observed_at, now, max_screen_age_ms);
  hash64('pep_provider_receipt_sha256', pep.provider_receipt_sha256);

  const decision = verifyHashedObject('onboarding_decision', bundle.operator_decision, 'decision_sha256');
  if (decision.decision !== 'APPROVE') throw new Error('onboarding_not_approved');
  if (decision.subject_binding_sha256 !== subject) throw new Error('onboarding_decision_subject_mismatch');
  if (!['LOW', 'MEDIUM', 'HIGH'].includes(decision.risk_class)) throw new Error('onboarding_risk_class_invalid');
  fresh('onboarding_decision', decision.decided_at, now, max_decision_age_ms);
  hash64('onboarding_operator_binding_sha256', decision.operator_binding_sha256);

  const body = {
    schema: 'g-bank-customer-onboarding-proof/v2',
    subject_binding_sha256: subject,
    identity_evidence_sha256: identity.evidence_sha256,
    sanctions_evidence_sha256: sanctions.evidence_sha256,
    pep_evidence_sha256: pep.evidence_sha256,
    operator_decision_sha256: decision.decision_sha256,
    risk_class: decision.risk_class,
    bundle_sha256: bundle.bundle_sha256,
    verified_at: new Date(now).toISOString(),
    technical_gate_only: true,
    grants_regulatory_authorization: false,
  };
  return Object.freeze({ ...body, proof_sha256: sha256(canonicalJson(body)) });
}

class CustomerOnboardingService {
  constructor({ customers }) {
    if (!customers || typeof customers.get !== 'function' || typeof customers.transition !== 'function') throw new Error('customer_registry_required');
    this.customers = customers;
  }

  startReview({ customer_id, evidence_sha256, now = Date.now() }) {
    return this.customers.transition({
      customer_id,
      expected_status: 'PROSPECT',
      to_status: 'REVIEW',
      decision_evidence_sha256: hash64('review_start_evidence_sha256', evidence_sha256),
      reason: 'CUSTOMER_DUE_DILIGENCE_REVIEW',
      now,
    });
  }

  activate({ customer_id, onboardingBundle, now = Date.now() }) {
    const customer = this.customers.get(customer_id);
    if (customer.status !== 'REVIEW') throw new Error('customer_not_in_review');
    const proof = verifyCustomerOnboardingBundle(onboardingBundle, {
      subject_binding_sha256: customer.subject_binding_sha256,
      now,
    });
    const active = this.customers.transition({
      customer_id,
      expected_status: 'REVIEW',
      to_status: 'ACTIVE',
      decision_evidence_sha256: proof.proof_sha256,
      reason: 'TECHNICAL_ONBOARDING_GATES_SATISFIED',
      now,
    });
    return Object.freeze({ customer: active, onboarding_proof: proof });
  }

  reject({ customer_id, decision_evidence_sha256, reason = 'ONBOARDING_REJECTED', now = Date.now() }) {
    return this.customers.transition({
      customer_id,
      expected_status: 'REVIEW',
      to_status: 'REJECTED',
      decision_evidence_sha256: hash64('customer_rejection_evidence_sha256', decision_evidence_sha256),
      reason,
      now,
    });
  }
}

module.exports = { verifyCustomerOnboardingBundle, CustomerOnboardingService };
