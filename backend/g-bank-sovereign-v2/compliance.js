'use strict';

const { canonicalJson, sha256 } = require('../g-bank-live-v1/canonical');

function assertSha256(name, value) {
  const v = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) throw new Error(`${name}_invalid`);
  return v;
}

function assertFresh(name, observedAt, now, maxAgeMs) {
  const t = Date.parse(observedAt);
  if (!Number.isFinite(t)) throw new Error(`${name}_observed_at_invalid`);
  if (t > now + 30000 || now - t > maxAgeMs) throw new Error(`${name}_stale`);
  return t;
}

function verifyComplianceBundle(bundle, {
  now = Date.now(),
  max_screen_age_ms = 15 * 60 * 1000,
  max_vop_age_ms = 15 * 60 * 1000,
  require_vop_match = true,
} = {}) {
  if (!bundle || typeof bundle !== 'object') throw new Error('compliance_bundle_required');

  const sanctions = bundle.sanctions_screen;
  if (!sanctions || sanctions.result !== 'CLEAR') throw new Error('sanctions_screen_not_clear');
  assertFresh('sanctions_screen', sanctions.observed_at, now, max_screen_age_ms);
  assertSha256('sanctions_evidence_sha256', sanctions.evidence_sha256);

  const aml = bundle.aml_gate;
  if (!aml || aml.result !== 'PASS') throw new Error('aml_gate_not_passed');
  assertFresh('aml_gate', aml.observed_at, now, max_screen_age_ms);
  assertSha256('aml_evidence_sha256', aml.evidence_sha256);

  const vop = bundle.verification_of_payee;
  if (require_vop_match) {
    if (!vop || vop.result !== 'MATCH') throw new Error('verification_of_payee_not_match');
    assertFresh('verification_of_payee', vop.observed_at, now, max_vop_age_ms);
    assertSha256('vop_evidence_sha256', vop.evidence_sha256);
  } else if (vop) {
    if (!['MATCH', 'CLOSE_MATCH', 'NO_MATCH', 'NOT_AVAILABLE'].includes(vop.result)) {
      throw new Error('verification_of_payee_result_invalid');
    }
    assertFresh('verification_of_payee', vop.observed_at, now, max_vop_age_ms);
    assertSha256('vop_evidence_sha256', vop.evidence_sha256);
  }

  const proof = {
    schema: 'g-bank-compliance-proof/v2',
    sanctions_evidence_sha256: sanctions.evidence_sha256,
    aml_evidence_sha256: aml.evidence_sha256,
    vop_result: vop?.result || null,
    vop_evidence_sha256: vop?.evidence_sha256 || null,
    verified_at: new Date(now).toISOString(),
  };
  proof.proof_sha256 = sha256(canonicalJson(proof));
  return Object.freeze(proof);
}

module.exports = { verifyComplianceBundle, assertSha256, assertFresh };
