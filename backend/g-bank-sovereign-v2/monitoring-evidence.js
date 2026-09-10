'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function hash64(name, value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}_invalid`);
  return hash;
}

function verifyHashBound(name, value, hashField) {
  if (!value || typeof value !== 'object') throw new Error(`${name}_required`);
  const supplied = hash64(`${name}_${hashField}`, value[hashField]);
  const { [hashField]: omitted, ...body } = value;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error(`${name}_hash_mismatch`);
  return value;
}

function observedTime(name, value, now, maxAgeMs) {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) throw new Error(`${name}_observed_at_invalid`);
  if (time > now + 30000) throw new Error(`${name}_observed_at_future`);
  if (now - time > maxAgeMs) throw new Error(`${name}_stale`);
  return time;
}

function verifyMonitoringEvidence(evidence, {
  subject_binding_sha256,
  now = Date.now(),
  max_kyc_age_ms = 365 * 24 * 60 * 60 * 1000,
  max_screen_age_ms = 24 * 60 * 60 * 1000,
} = {}) {
  const subject = hash64('monitoring_subject_binding_sha256', subject_binding_sha256);
  if (!evidence || typeof evidence !== 'object') throw new Error('monitoring_evidence_required');

  const kyc = verifyHashBound('kyc_refresh', evidence.kyc_refresh, 'evidence_sha256');
  if (kyc.schema !== 'g-bank-kyc-refresh-evidence/v2') throw new Error('kyc_refresh_schema_invalid');
  if (kyc.state !== 'VERIFIED') throw new Error('kyc_refresh_not_verified');
  if (kyc.subject_binding_sha256 !== subject) throw new Error('kyc_refresh_subject_mismatch');
  observedTime('kyc_refresh', kyc.observed_at, now, max_kyc_age_ms);

  const sanctions = verifyHashBound('sanctions_rescreen', evidence.sanctions_rescreen, 'evidence_sha256');
  if (sanctions.schema !== 'g-bank-sanctions-rescreen-evidence/v2') throw new Error('sanctions_rescreen_schema_invalid');
  if (sanctions.result !== 'CLEAR') throw new Error('sanctions_rescreen_not_clear');
  if (sanctions.subject_binding_sha256 !== subject) throw new Error('sanctions_rescreen_subject_mismatch');
  observedTime('sanctions_rescreen', sanctions.observed_at, now, max_screen_age_ms);

  const pep = verifyHashBound('pep_rescreen', evidence.pep_rescreen, 'evidence_sha256');
  if (pep.schema !== 'g-bank-pep-rescreen-evidence/v2') throw new Error('pep_rescreen_schema_invalid');
  if (!['CLEAR', 'EDD_PASS'].includes(pep.result)) throw new Error('pep_rescreen_not_clear');
  if (pep.subject_binding_sha256 !== subject) throw new Error('pep_rescreen_subject_mismatch');
  observedTime('pep_rescreen', pep.observed_at, now, max_screen_age_ms);

  const body = {
    schema: 'g-bank-continuous-monitoring-evidence-proof/v2',
    subject_binding_sha256: subject,
    kyc_evidence_sha256: kyc.evidence_sha256,
    sanctions_evidence_sha256: sanctions.evidence_sha256,
    pep_evidence_sha256: pep.evidence_sha256,
    pep_result: pep.result,
    verified_at: new Date(now).toISOString(),
    technical_gate_only: true,
    regulatory_determination_made: false,
  };
  return Object.freeze({ ...body, proof_sha256: sha256(canonicalJson(body)) });
}

module.exports = { verifyMonitoringEvidence, verifyHashBound, hash64 };
