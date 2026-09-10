'use strict';

function sha256Present(value) {
  return /^[0-9a-f]{64}$/i.test(String(value || ''));
}

function assessSovereignReadiness({ env = process.env, transportPreflight = null } = {}) {
  const checks = {
    live_flag: env.G_BANK_ENABLE_LIVE === 'true',
    external_actions_flag: env.G_BANK_EXTERNAL_ACTIONS_ENABLED === 'true',
    direct_settlement_flag: env.G_BANK_DIRECT_SETTLEMENT_ENABLED === 'true',
    simulated_live_success_forbidden: env.G_BANK_SIMULATED_LIVE_SUCCESS !== 'true',
    approval_secret_present: Buffer.byteLength(String(env.G_BANK_SOVEREIGN_APPROVAL_SECRET || '')) >= 32,
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

  const staticKeys = Object.keys(checks).filter(k => !k.startsWith('transport_live_') && !k.startsWith('transport_external_') && k !== 'transport_scheme_supported' && k !== 'settlement_system_identified');
  const static_configuration_ready = staticKeys.every(k => checks[k] === true);
  const external_transport_verified = checks.transport_live_authenticated && checks.transport_live_connected && checks.transport_external_receipt_present && checks.transport_scheme_supported && checks.settlement_system_identified;
  const direct_live_ready = static_configuration_ready && external_transport_verified;

  return Object.freeze({
    schema: 'g-bank-sovereign-readiness/v2',
    state: direct_live_ready ? 'DIRECT_LIVE_READY' : 'DIRECT_LIVE_BLOCKED',
    static_configuration_ready,
    external_transport_verified,
    direct_live_ready,
    checks,
    value_movement_permitted_by_readiness: direct_live_ready,
    note: direct_live_ready is a technical gate only; it does not itself create legal authorization or scheme membership,
  });
}

module.exports = { assessSovereignReadiness, sha256Present };
