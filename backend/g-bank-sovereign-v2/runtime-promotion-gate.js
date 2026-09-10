'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');
const { verifyTechnicalPromotionCertificate, verifyReadiness } = require('./promotion-certificate');

function hash64(name, value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}_invalid`);
  return hash;
}

function readJsonFile(name, filePath) {
  const resolved = path.resolve(String(filePath || ''));
  if (!filePath || !fs.existsSync(resolved)) throw new Error(`${name}_file_required`);
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${name}_file_invalid`);
  let value;
  try { value = JSON.parse(fs.readFileSync(resolved, 'utf8')); }
  catch { throw new Error(`${name}_json_invalid`); }
  return Object.freeze({ resolved, value });
}

const RUNTIME_BINDINGS = Object.freeze([
  ['legal_authorization_evidence_sha256', 'G_BANK_LEGAL_AUTHORIZATION_EVIDENCE_SHA256'],
  ['scheme_participation_evidence_sha256', 'G_BANK_SCHEME_PARTICIPATION_EVIDENCE_SHA256'],
  ['settlement_access_evidence_sha256', 'G_BANK_SETTLEMENT_ACCESS_EVIDENCE_SHA256'],
  ['production_identity_evidence_sha256', 'G_BANK_PRODUCTION_IDENTITY_EVIDENCE_SHA256'],
  ['prudential_audit_sha256', 'G_BANK_PRUDENTIAL_AUDIT_SHA256'],
  ['operational_resilience_sha256', 'G_BANK_OPERATIONAL_RESILIENCE_SHA256'],
  ['treasury_assessment_sha256', 'G_BANK_TREASURY_ASSESSMENT_SHA256'],
  ['customer_monitoring_audit_sha256', 'G_BANK_CUSTOMER_MONITORING_AUDIT_SHA256'],
  ['recovery_audit_sha256', 'G_BANK_RECOVERY_AUDIT_SHA256'],
]);

function verifyRuntimePromotionGate({ env = process.env, now = Date.now() } = {}) {
  const readinessFile = readJsonFile('runtime_readiness', env.G_BANK_RUNTIME_READINESS_FILE);
  const promotionFile = readJsonFile('runtime_promotion_certificate', env.G_BANK_RUNTIME_PROMOTION_CERTIFICATE_FILE);
  const readiness = readinessFile.value;
  const certificate = promotionFile.value;

  verifyReadiness(readiness);
  verifyTechnicalPromotionCertificate(certificate, { readiness, now });

  const configuredCertificate = hash64('promotion_certificate_sha256', env.G_BANK_PROMOTION_CERTIFICATE_SHA256);
  if (configuredCertificate !== String(certificate.certificate_sha256 || '').toLowerCase()) throw new Error('runtime_promotion_certificate_binding_mismatch');

  const mismatches = [];
  for (const [certificateField, envField] of RUNTIME_BINDINGS) {
    const configured = hash64(envField.toLowerCase(), env[envField]);
    const certified = hash64(certificateField, certificate.evidence_bindings?.[certificateField]);
    if (configured !== certified) mismatches.push(certificateField);
  }
  if (mismatches.length) throw new Error(`runtime_promotion_evidence_binding_mismatch:${mismatches.sort().join(',')}`);

  const body = {
    schema: 'g-bank-runtime-promotion-gate/v2',
    state: 'PASS',
    readiness_snapshot_sha256: sha256(canonicalJson(readiness)),
    promotion_certificate_sha256: certificate.certificate_sha256,
    state_root_sha256: certificate.state_root_sha256,
    customer_monitoring_audit_sha256: certificate.evidence_bindings.customer_monitoring_audit_sha256,
    recovery_audit_sha256: certificate.evidence_bindings.recovery_audit_sha256,
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
    runtime_submit_gate_satisfied: true,
    checked_at: new Date(now).toISOString(),
  };
  return Object.freeze({ ...body, gate_sha256: sha256(canonicalJson(body)) });
}

module.exports = { verifyRuntimePromotionGate, readJsonFile, RUNTIME_BINDINGS };
