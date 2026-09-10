'use strict';

function sha256Present(value) {
  return /^[0-9a-f]{64}$/i.test(String(value || ''));
}

function positiveInt(value) {
  const n = Number(value);
  return Number.isSafeInteger(n) && n >= 1;
}

function assessSovereignReadiness({ env = process.env, transportPreflight = null, governance = null } = {}) {
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
  const staticKeys = Object.keys(checks).filter(k => !transportKeys.has(k));
  const static_configuration_ready = staticKeys.every(k => checks[k] === true);
  const external_transport_verified = [...transportKeys].every(k => checks[k] === true);
  const direct_live_ready = static_configuration_ready && external_transport_verified;

  return Object.freeze({
    schema: 'g-bank-sovereign-readiness/v2',
    state: direct_live_ready ? 'DIRECT_LIVE_READY' : 'DIRECT_LIVE_BLOCKED',
    static_configuration_ready,
    external_transport_verified,
    direct_live_ready,
    checks,
    value_movement_permitted_by_readiness: direct_live_ready,
    note: 'direct_live_ready is a technical gate only; it does not itself create legal authorization, scheme membership, central-bank access, or settlement rights',
  });
}

module.exports = { assessSovereignReadiness, sha256Present, positiveInt };
