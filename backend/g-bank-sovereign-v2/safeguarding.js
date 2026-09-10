'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function nonNegative(name, value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${name}_invalid`);
  return n;
}

function assessSafeguarding({ customer_liabilities_minor, safeguarded_assets_minor, pending_outbound_holds_minor = 0, required_buffer_minor = 0, evidence_sha256 = null, now = Date.now() }) {
  const liabilities = nonNegative('customer_liabilities_minor', customer_liabilities_minor);
  const assets = nonNegative('safeguarded_assets_minor', safeguarded_assets_minor);
  const holds = nonNegative('pending_outbound_holds_minor', pending_outbound_holds_minor);
  const buffer = nonNegative('required_buffer_minor', required_buffer_minor);
  const evidence = evidence_sha256 === null ? null : String(evidence_sha256).toLowerCase();
  if (evidence !== null && !/^[0-9a-f]{64}$/.test(evidence)) throw new Error('safeguarding_evidence_sha256_invalid');

  const protectedLiabilities = liabilities + holds;
  if (!Number.isSafeInteger(protectedLiabilities)) throw new Error('safeguarding_liability_overflow');
  const required = protectedLiabilities + buffer;
  if (!Number.isSafeInteger(required)) throw new Error('safeguarding_requirement_overflow');
  const surplus = assets - required;

  const body = {
    schema: 'g-bank-safeguarding-assessment/v2',
    state: surplus >= 0 ? 'PASS' : 'BLOCK',
    customer_liabilities_minor: liabilities,
    pending_outbound_holds_minor: holds,
    required_buffer_minor: buffer,
    required_safeguarded_minor: required,
    safeguarded_assets_minor: assets,
    surplus_minor: surplus,
    evidence_sha256: evidence,
    assessed_at: new Date(now).toISOString(),
  };
  return Object.freeze({ ...body, assessment_sha256: sha256(canonicalJson(body)) });
}

module.exports = { assessSafeguarding };
