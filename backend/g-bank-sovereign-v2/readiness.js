'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function sha256Present(value) {
  return /^[0-9a-f]{64}$/i.test(String(value || ''));
}

function normalizedHash(value) {
  return sha256Present(value) ? String(value).toLowerCase() : null;
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

function timestampFresh(value, now, maxAgeMs = 60000) {
  const ts = Date.parse(value);
  return Number.isFinite(ts) && ts <= now + 30000 && now - ts <= maxAgeMs;
}

function assessSovereignReadiness({
  env = process.env,
  transportPreflight = null,
  governance = null,
  prudential = null,
  monitoringAudit = null,
  recoveryAudit = null,
  haAudit = null,
  haDeploymentAudit = null,
  now = Date.now(),
} = {}) {
  const safeguarding = prudential?.safeguarding || null;
  const liquidity = prudential?.liquidity || null;
  const invariantAudit = prudential?.invariant_audit || null;
  const operational = prudential?.operational_resilience || null;
  const treasury = prudential?.treasury || null;
  const configuredPrudentialHash = normalizedHash(env.G_BANK_PRUDENTIAL_AUDIT_SHA256);
  const configuredOperationalHash = normalizedHash(env.G_BANK_OPERATIONAL_RESILIENCE_SHA256);
  const configuredTreasuryHash = normalizedHash(env.G_BANK_TREASURY_ASSESSMENT_SHA256);
  const configuredMonitoringHash = normalizedHash(env.G_BANK_CUSTOMER_MONITORING_AUDIT_SHA256);
  const configuredRecoveryHash = normalizedHash(env.G_BANK_RECOVERY_AUDIT_SHA256);
  const configuredHAHash = normalizedHash(env.G_BANK_HA_AUDIT_SHA256);
  const configuredHADeploymentHash = normalizedHash(env.G_BANK_HA_DEPLOYMENT_AUDIT_SHA256);

  const evidence_bindings = Object.freeze({
    legal_authorization_evidence_sha256: normalizedHash(env.G_BANK_LEGAL_AUTHORIZATION_EVIDENCE_SHA256),
    scheme_participation_evidence_sha256: normalizedHash(env.G_BANK_SCHEME_PARTICIPATION_EVIDENCE_SHA256),
    settlement_access_evidence_sha256: normalizedHash(env.G_BANK_SETTLEMENT_ACCESS_EVIDENCE_SHA256),
    production_identity_evidence_sha256: normalizedHash(env.G_BANK_PRODUCTION_IDENTITY_EVIDENCE_SHA256),
    transport_preflight_receipt_sha256: normalizedHash(transportPreflight?.external_receipt_sha256),
    prudential_audit_sha256: configuredPrudentialHash,
    operational_resilience_sha256: configuredOperationalHash,
    treasury_assessment_sha256: configuredTreasuryHash,
    customer_monitoring_audit_sha256: configuredMonitoringHash,
    recovery_audit_sha256: configuredRecoveryHash,
    ha_audit_sha256: configuredHAHash,
    ha_deployment_audit_sha256: configuredHADeploymentHash,
  });
  const recoveryCheckpointRoot = normalizedHash(recoveryAudit?.checkpoint_state_root_sha256);
  const haCheckpointRoot = normalizedHash(haAudit?.checkpoint_state_root_sha256);
  const haVoterJournalRoot = normalizedHash(haAudit?.voter_journal_root_sha256);
  const haClusterAuthorityRoot = normalizedHash(haAudit?.cluster_authority_root_sha256);
  const haFenceValidUntil = Number.isFinite(Date.parse(haAudit?.fence_valid_until)) ? new Date(Date.parse(haAudit.fence_valid_until)).toISOString() : null;
  const haQuorum = Number(haAudit?.quorum);
  const haActiveVoters = Number(haAudit?.active_voter_count);
  const haJournalStores = Number(haAudit?.voter_journal_store_count);
  const durableFenceSigners = Number(haAudit?.durable_fence_signer_count);
  const durableCommitSigners = Number(haAudit?.durable_commit_signer_count);
  const transitionCount = Number(haAudit?.cluster_transition_count);
  const transitionHead = normalizedHash(haAudit?.cluster_transition_head_sha256);

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
    customer_monitoring_binding_present: sha256Present(configuredMonitoringHash),
    customer_monitoring_pass: assessmentValid(monitoringAudit, 'g-bank-monitoring-fleet-audit/v2', 'audit_sha256'),
    customer_monitoring_binding_matches: sha256Present(configuredMonitoringHash) && configuredMonitoringHash === String(monitoringAudit?.audit_sha256 || '').toLowerCase(),
    recovery_audit_binding_present: sha256Present(configuredRecoveryHash),
    recovery_audit_pass: assessmentValid(recoveryAudit, 'g-bank-recovery-readiness-audit/v2', 'audit_sha256'),
    recovery_audit_binding_matches: sha256Present(configuredRecoveryHash) && configuredRecoveryHash === String(recoveryAudit?.audit_sha256 || '').toLowerCase(),
    recovery_checkpoint_root_present: sha256Present(recoveryCheckpointRoot),
    recovery_no_external_rights: recoveryAudit?.grants_external_rights === false,
    recovery_no_live_activation: recoveryAudit?.activates_live_execution === false,
    recovery_no_value_movement: recoveryAudit?.permits_value_movement === false,
    ha_audit_binding_present: sha256Present(configuredHAHash),
    ha_audit_pass: assessmentValid(haAudit, 'g-bank-ha-readiness-audit/v2', 'audit_sha256'),
    ha_audit_binding_matches: sha256Present(configuredHAHash) && configuredHAHash === String(haAudit?.audit_sha256 || '').toLowerCase(),
    ha_cluster_authority_root_present: sha256Present(haClusterAuthorityRoot),
    ha_cluster_transition_chain_consistent: Number.isSafeInteger(transitionCount) && transitionCount >= 0 && ((transitionCount === 0 && haAudit?.cluster_transition_head_sha256 === null) || (transitionCount > 0 && sha256Present(transitionHead))),
    ha_checkpoint_root_present: sha256Present(haCheckpointRoot),
    ha_checkpoint_matches_recovery: sha256Present(haCheckpointRoot) && sha256Present(recoveryCheckpointRoot) && haCheckpointRoot === recoveryCheckpointRoot,
    ha_quorum_present: Number.isSafeInteger(haQuorum) && haQuorum >= 2 && Number.isSafeInteger(haActiveVoters) && haActiveVoters >= haQuorum,
    ha_voter_journal_root_present: sha256Present(haVoterJournalRoot),
    ha_voter_journal_store_coverage_complete: Number.isSafeInteger(haJournalStores) && Number.isSafeInteger(haActiveVoters) && haJournalStores === haActiveVoters,
    ha_durable_fence_quorum: Number.isSafeInteger(durableFenceSigners) && Number.isSafeInteger(haQuorum) && durableFenceSigners >= haQuorum,
    ha_durable_commit_quorum: Number.isSafeInteger(durableCommitSigners) && Number.isSafeInteger(haQuorum) && durableCommitSigners >= haQuorum,
    ha_fence_current: Boolean(haFenceValidUntil) && Date.parse(haFenceValidUntil) > now,
    ha_no_external_rights: haAudit?.grants_external_rights === false,
    ha_no_value_movement: haAudit?.permits_value_movement_by_itself === false,
    ha_control_plane_does_not_fake_network: haAudit?.distributed_network_verified === false,
    ha_deployment_binding_present: sha256Present(configuredHADeploymentHash),
    ha_deployment_pass: assessmentValid(haDeploymentAudit, 'g-bank-ha-deployment-audit/v2', 'audit_sha256'),
    ha_deployment_binding_matches: sha256Present(configuredHADeploymentHash) && configuredHADeploymentHash === String(haDeploymentAudit?.audit_sha256 || '').toLowerCase(),
    ha_deployment_cluster_matches_control_plane: Boolean(haAudit?.cluster_sha256) && haDeploymentAudit?.cluster_sha256 === haAudit.cluster_sha256,
    ha_deployment_fresh: timestampFresh(haDeploymentAudit?.audited_at, now, 60000),
    ha_deployment_observation_fresh: timestampFresh(haDeploymentAudit?.observed_at, now, 60000),
    ha_distributed_network_verified: haDeploymentAudit?.distributed_network_verified === true,
    ha_all_active_voters_healthy: haDeploymentAudit?.all_active_voters_healthy === true,
    ha_unique_machine_identities_verified: haDeploymentAudit?.unique_machine_identities_verified === true,
    ha_unique_endpoints_verified: haDeploymentAudit?.unique_endpoints_verified === true,
    ha_unique_failure_domains_verified: haDeploymentAudit?.unique_failure_domains_verified === true,
    ha_deployment_no_external_rights: haDeploymentAudit?.grants_external_rights === false,
    ha_deployment_no_value_movement: haDeploymentAudit?.permits_value_movement_by_itself === false,
    transport_module_present: Boolean(String(env.G_BANK_SETTLEMENT_TRANSPORT_MODULE || '')),
    settlement_authorization_binding_present: sha256Present(env.G_BANK_SETTLEMENT_AUTHORIZATION_SHA256),
    legal_authorization_evidence_binding_present: sha256Present(evidence_bindings.legal_authorization_evidence_sha256),
    scheme_participation_evidence_binding_present: sha256Present(evidence_bindings.scheme_participation_evidence_sha256),
    settlement_access_evidence_binding_present: sha256Present(evidence_bindings.settlement_access_evidence_sha256),
    production_identity_evidence_binding_present: sha256Present(evidence_bindings.production_identity_evidence_sha256),
    transport_live_authenticated: transportPreflight?.environment === 'LIVE' && transportPreflight?.authenticated === true,
    transport_live_connected: transportPreflight?.connected === true,
    transport_external_receipt_present: sha256Present(evidence_bindings.transport_preflight_receipt_sha256),
    transport_scheme_supported: ['SCT', 'SCT_INST'].includes(transportPreflight?.scheme),
    settlement_system_identified: Boolean(transportPreflight?.settlement_system),
  };

  const transportKeys = new Set(['transport_live_authenticated','transport_live_connected','transport_external_receipt_present','transport_scheme_supported','settlement_system_identified']);
  const prudentialKeys = new Set(['prudential_audit_binding_present','safeguarding_pass','liquidity_pass','invariant_audit_pass','prudential_audit_binding_matches','treasury_binding_present','treasury_pass','treasury_binding_matches']);
  const operationalKeys = new Set(['operational_resilience_binding_present','operational_resilience_pass','operational_resilience_binding_matches']);
  const monitoringKeys = new Set(['customer_monitoring_binding_present','customer_monitoring_pass','customer_monitoring_binding_matches']);
  const recoveryKeys = new Set(['recovery_audit_binding_present','recovery_audit_pass','recovery_audit_binding_matches','recovery_checkpoint_root_present','recovery_no_external_rights','recovery_no_live_activation','recovery_no_value_movement']);
  const haKeys = new Set([
    'ha_audit_binding_present','ha_audit_pass','ha_audit_binding_matches','ha_cluster_authority_root_present','ha_cluster_transition_chain_consistent',
    'ha_checkpoint_root_present','ha_checkpoint_matches_recovery','ha_quorum_present','ha_voter_journal_root_present','ha_voter_journal_store_coverage_complete',
    'ha_durable_fence_quorum','ha_durable_commit_quorum','ha_fence_current','ha_no_external_rights','ha_no_value_movement','ha_control_plane_does_not_fake_network',
    'ha_deployment_binding_present','ha_deployment_pass','ha_deployment_binding_matches','ha_deployment_cluster_matches_control_plane',
    'ha_deployment_fresh','ha_deployment_observation_fresh','ha_distributed_network_verified','ha_all_active_voters_healthy',
    'ha_unique_machine_identities_verified','ha_unique_endpoints_verified','ha_unique_failure_domains_verified','ha_deployment_no_external_rights','ha_deployment_no_value_movement',
  ]);
  const staticKeys = Object.keys(checks).filter(k => !transportKeys.has(k) && !prudentialKeys.has(k) && !operationalKeys.has(k) && !monitoringKeys.has(k) && !recoveryKeys.has(k) && !haKeys.has(k));
  const static_configuration_ready = staticKeys.every(k => checks[k] === true);
  const external_transport_verified = [...transportKeys].every(k => checks[k] === true);
  const prudential_controls_verified = [...prudentialKeys].every(k => checks[k] === true);
  const operational_controls_verified = [...operationalKeys].every(k => checks[k] === true);
  const customer_monitoring_verified = [...monitoringKeys].every(k => checks[k] === true);
  const recovery_controls_verified = [...recoveryKeys].every(k => checks[k] === true);
  const ha_controls_verified = [...haKeys].every(k => checks[k] === true);
  const direct_live_ready = static_configuration_ready && external_transport_verified && prudential_controls_verified && operational_controls_verified && customer_monitoring_verified && recovery_controls_verified && ha_controls_verified;

  return Object.freeze({
    schema: 'g-bank-sovereign-readiness/v2',
    state: direct_live_ready ? 'DIRECT_LIVE_READY' : 'DIRECT_LIVE_BLOCKED',
    static_configuration_ready,
    external_transport_verified,
    prudential_controls_verified,
    operational_controls_verified,
    customer_monitoring_verified,
    recovery_controls_verified,
    ha_controls_verified,
    ha_deployment_verified: checks.ha_distributed_network_verified && checks.ha_deployment_pass && checks.ha_deployment_fresh,
    direct_live_ready,
    checks,
    evidence_bindings,
    recovery_checkpoint_state_root_sha256: recoveryCheckpointRoot,
    ha_checkpoint_state_root_sha256: haCheckpointRoot,
    ha_voter_journal_root_sha256: haVoterJournalRoot,
    ha_cluster_authority_root_sha256: haClusterAuthorityRoot,
    ha_fence_valid_until: haFenceValidUntil,
    transport_scheme: transportPreflight?.scheme || null,
    settlement_system: transportPreflight?.settlement_system || null,
    value_movement_permitted_by_readiness: direct_live_ready,
    note: 'direct_live_ready is a technical gate only; canonical joint-quorum cluster authority, durable quorum journals and a fresh trusted external distributed-HA attestation are mandatory and still do not create legal authorization, scheme membership, central-bank access, or settlement rights',
  });
}

module.exports = { assessSovereignReadiness, sha256Present, positiveInt, assessmentValid, normalizedHash, timestampFresh };
