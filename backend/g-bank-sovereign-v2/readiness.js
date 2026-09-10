'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function sha256Present(value) {
  return /^[0-9a-f]{64}$/i.test(String(value || ''));
}

function positiveInt(value) {
  const n = Number(value);
  return Number.isSafeInteger(n) && n >= 1;
}

function assessmentValid(value, schema, hashField) {
  if (!value || value.schema !== schema || value.state !== 'PASS' || !sha256Present(value[hashField])) return false;
  const supplied = String(value[hashField]).toLowerCase();
  const { [hashField]: omitted, ...body } = value;
  return sha256(canonicalJson(body)) === supplied;
}

function assessSovereignReadiness({ env = process.env, transportPreflight = null, governance = null, prudential = null } = {}) {
  const safeguarding = prudential?.safeguarding || null;
  const liquidity = prudential?.liquidity || null;
  const invariantAudit = prudential?.invariant_audit || null;
  const operational = prudential?.operational_resilience || null;
  const treasury = prudential?.treasury || null;
  const configuredPrudentialHash = String(env.G_BANK_PRUDENTIAL_AUDIT_SHA256 || '').toLowerCase();
  const configuredOperationalHash = String(env.G_BANK_OPERATIONAL_RESILIENCE_SHA256 || '').toLowerCase();
  const configuredTreasuryHash = String(env.G_BANK_TREASURY_ASSESSMENT_SHA256 || '').toLowerCase();

  const checks = {
    live_flag: env.G_BANK_ENABLE_LIVE === 'true',
    external_actions_flag: env.G_BANK_EXTERNAL_ACTIONS_ENABLED === 'true',
    direct_settlement_flag: env.G_BANK_DIRECT_SETTLEMENT_ENABLED === 'true',
    simulated_live_success_forbidden: env.G_BANK_SIMULATED_LIVE_SUCCESS !== 'true',
    approval_secret_present: Buffer.byteLength(String(env.G_BANK_SOVEREIGN_APPROVAL_SECRET || '')) >= 32,
    governance_required: env.G_BANK_GOVERNANCE_REQUIRED === 'true',
    risk_policy_binding_present: sha256Present(governance?.policy_sha256),
    authority_set_binding_present: sha256Present(governance?.authority_set_sha256),
    policy_epoch_present: positiveInt(governance?.policy_epoch),
    authority_epoch_present: positiveInt(governance?.authority_epoch),
    normal_quorum_present: positiveInt(governance?.normal_quorum),
    high_value_quorum_dual_control: Number.isSafeInteger(Number(governance?.high_value_quorum)) && Number(governance.high_value_quorum) >= 2,
    prudential_audit_binding_present: sha256Present(configuredPrudentialHash),
    safeguarding_pass: assessmentValid(safeguarding, 'g-bank-safeguarding-assessment/v2', 'assessment_sha256'),
    liquidity_pass: assessmentValid(liquidity, 'g-bank-liquidity-assessment/v2', 'assessment_sha256'),
    invariant_audit_pass: assessmentValid(invariantAudit, 'g-bank-sovereign-invariant-audit/v2', 'audit_sha256'),
    prudential_audit_binding_matches: sha256Present(configuredPrudentialHash) && configuredPrudentialHash === String(invariantAudit?.audit_sha256 || '').toLowerCase(),
    operational_resilience_binding_present: sha256Present(configuredOperationalHash),
    operational_resilience_pass: assessmentValid(operational, 'g-bank-operational-resilience-assessment/v2', 'assessment_sha256'),
    operational_resilience_binding_matches: sha256Present(configuredOperationalHash) && configuredOperationalHash === String(operational?.assessment_sha256 || '').toLowerCase(),
    treasury_binding_present: sha256Present(configuredTreasuryHash),
    treasury_pass: assessmentValid(treasury, 'g-bank-treasury-position/v2', 'assessment_sha256'),
    treasury_binding_matches: sha256Present(configuredTreasuryHash) && configuredTreasuryHash === String(treasury?.assessment_sha256 || '').toLowerCase(),
    transport_module_present: Boolean(String(env.G_BANK_SETTLEMENT_TRANSPORT_MODULE || '')),
    settlement_authorization_binding_present: sha256Present(env.G_BANK_SETTLEMENT_AUTHORIZATION_SHA256),
    legal_authorization_evidence_binding_present: sha256Present(env.G_BANK_LEGAL_AUTHORIZATION_EVIDENCE_SHA256),
    scheme_participation_evidence_binding_present: sha256Present(env.G_BANK_SCHEME_PARTICIPATION_EVIDENCE_SHA256),
    settlement_access_evidence_binding_present: sha256Present(env.G_BANK_SETTLEMENT_ACCESS_EVIDENCE_SHA256),
    production_identity_evidence_binding_present: sha256Present(env.G_BANK_PRODUCTION_IDENTITY_EVIDENCE_SHA256),
    transport_live_authenticated: transportPreflight?.environment === 'LIVE' && transportPreflight?.authenticated === true,
    transport_live_connected: transportPreflight?.connected === true,
    transport_external_receipt_present: sha256Present(transportPreflight?.external_receipt_sha256),
    transport_scheme_supported: ['SCT', 'SCT_INST'].includes(transportPreflight?.scheme),
    settlement_system_identified: Boolean(transportPreflight?.settlement_system),
  };

  const transportKeys = new Set([
    'transport_live_authenticated',
    'transport_live_connected',
    'transport_external_receipt_present',
    'transport_scheme_supported',
    'settlement_system_identified',
  ]);
  const prudentialKeys = new Set([
    'prudential_audit_binding_present',
    'safeguarding_pass',
    'liquidity_pass',
    'invariant_audit_pass',
    'prudential_audit_binding_matches',
    'treasury_binding_present',
    'treasury_pass',
    'treasury_binding_matches',
  ]);
  const operationalKeys = new Set([
    'operational_resilience_binding_present',
    'operational_resilience_pass',
    'operational_resilience_binding_matches',
  ]);
  const staticKeys = Object.keys(checks).filter(k => !transportKeys.has(k) && !prudentialKeys.has(k) && !operationalKeys.has(k));
  const static_configuration_ready = staticKeys.every(k => checks[k] === true);
  const external_transport_verified = [...transportKeys].every(k => checks[k] === true);
  const prudential_controls_verified = [...prudentialKeys].every(k => checks[k] === true);
  const operational_controls_verified = [...operationalKeys].every(k => checks[k] === true);
  const direct_live_ready = static_configuration_ready && external_transport_verified && prudential_controls_verified && operational_controls_verified;

  return Object.freeze({
    schema: 'g-bank-sovereign-readiness/v2',
    state: direct_live_ready ? 'DIRECT_LIVE_READY' : 'DIRECT_LIVE_BLOCKED',
    static_configuration_ready,
    external_transport_verified,
    prudential_controls_verified,
    operational_controls_verified,
    direct_live_ready,
    checks,
    value_movement_permitted_by_readiness: direct_live_ready,
    note: 'direct_live_ready is a technical gate only; it does not itself create legal authorization, scheme membership, central-bank access, or settlement rights',
  });
}

module.exports = { assessSovereignReadiness, sha256Present, positiveInt, assessmentValid };
