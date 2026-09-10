'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { isValidIban, normalizeIban } = require('./accounts');

function hash64(name, value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}_invalid`);
  return hash;
}

function verifyExternalIbanAssignment(evidence, { customer, iban, now = Date.now(), max_age_ms = 24 * 60 * 60 * 1000 } = {}) {
  if (!evidence || evidence.schema !== 'g-bank-external-iban-assignment-evidence/v2') throw new Error('external_iban_assignment_evidence_required');
  const supplied = hash64('external_iban_assignment_evidence_sha256', evidence.evidence_sha256);
  const { evidence_sha256, ...body } = evidence;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('external_iban_assignment_evidence_hash_mismatch');
  if (evidence.state !== 'ASSIGNED') throw new Error('external_iban_not_assigned');
  if (evidence.subject_binding_sha256 !== customer.subject_binding_sha256) throw new Error('external_iban_subject_mismatch');
  const normalized = normalizeIban(evidence.iban);
  if (!isValidIban(normalized) || normalized !== normalizeIban(iban)) throw new Error('external_iban_value_mismatch');
  const assignedAt = Date.parse(evidence.assigned_at);
  if (!Number.isFinite(assignedAt) || assignedAt > now + 30000 || now - assignedAt > max_age_ms) throw new Error('external_iban_assignment_stale');
  if (!String(evidence.issuer || '').trim()) throw new Error('external_iban_issuer_missing');
  hash64('external_iban_assignment_receipt_sha256', evidence.external_receipt_sha256);
  return true;
}

class CustomerAccountProvisioner {
  constructor({ customers, accounts }) {
    if (!customers || typeof customers.get !== 'function') throw new Error('customer_registry_required');
    if (!accounts || typeof accounts.register !== 'function') throw new Error('account_registry_required');
    this.customers = customers;
    this.accounts = accounts;
  }

  open({ customer_id, account_id, currency = 'EUR', iban = null, ibanAssignmentEvidence = null, metadata = {}, now = Date.now() }) {
    const customer = this.customers.get(customer_id);
    if (customer.status !== 'ACTIVE') throw new Error('customer_not_active_for_account_opening');
    const normalizedIban = iban ? normalizeIban(iban) : null;
    if (normalizedIban) verifyExternalIbanAssignment(ibanAssignmentEvidence, { customer, iban: normalizedIban, now });
    else if (ibanAssignmentEvidence) throw new Error('iban_assignment_evidence_without_iban');

    const account = this.accounts.register({
      account_id,
      type: 'CUSTOMER',
      currency,
      iban: normalizedIban,
      owner_binding_sha256: customer.subject_binding_sha256,
      metadata: {
        ...metadata,
        customer_id: customer.customer_id,
        customer_registry_record_sha256: customer.record_sha256,
        iban_source: normalizedIban ? 'VERIFIED_EXTERNAL_ASSIGNMENT' : 'UNASSIGNED',
        iban_assignment_evidence_sha256: normalizedIban ? ibanAssignmentEvidence.evidence_sha256 : null,
      },
    });

    const body = {
      schema: 'g-bank-customer-account-provisioning-proof/v2',
      customer_id: customer.customer_id,
      customer_record_sha256: customer.record_sha256,
      subject_binding_sha256: customer.subject_binding_sha256,
      account_id: account.account_id,
      account_currency: account.currency,
      iban: account.iban,
      iban_assignment_evidence_sha256: normalizedIban ? ibanAssignmentEvidence.evidence_sha256 : null,
      provisioned_at: new Date(now).toISOString(),
      local_iban_issuance_performed: false,
      grants_iban_issuance_authority: false,
    };
    return Object.freeze({ account, provisioning_proof: Object.freeze({ ...body, proof_sha256: sha256(canonicalJson(body)) }) });
  }
}

module.exports = { CustomerAccountProvisioner, verifyExternalIbanAssignment };
