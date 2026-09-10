'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { verifyRecoveryManifest } = require('./recovery-manifest');
const { verifyRecoveryAnchorRecord } = require('./recovery-anchor-store');
const { verifyRestoreCandidate } = require('./restore-verifier');

function finiteTime(name, value) {
  const ms = Date.parse(String(value || ''));
  if (!Number.isFinite(ms)) throw new Error(`${name}_invalid`);
  return ms;
}

function assessRecoveryReadiness({
  manifest,
  anchorStore,
  snapshot_root,
  checkpoint,
  max_age_ms = 15 * 60 * 1000,
  now = Date.now(),
}) {
  verifyRecoveryManifest(manifest);
  if (!anchorStore || typeof anchorStore.verify !== 'function' || typeof anchorStore.latest !== 'function') {
    throw new Error('recovery_anchor_store_required');
  }
  if (!checkpoint || checkpoint.schema !== 'g-bank-sovereign-state-checkpoint/v2') throw new Error('recovery_audit_checkpoint_required');

  const maxAge = Number(max_age_ms);
  if (!Number.isSafeInteger(maxAge) || maxAge < 60 * 1000 || maxAge > 24 * 60 * 60 * 1000) throw new Error('recovery_audit_max_age_invalid');

  const chain = anchorStore.verify();
  if (!chain.verified) throw new Error('recovery_anchor_chain_not_verified');
  const anchor = anchorStore.latest();
  if (!anchor) throw new Error('recovery_anchor_missing');
  verifyRecoveryAnchorRecord(anchor);

  const restore = verifyRestoreCandidate({ manifest, anchor, restore_root: snapshot_root, checkpoint });
  const createdAt = finiteTime('recovery_manifest_created_at', manifest.created_at);
  const anchoredAt = finiteTime('recovery_anchor_anchored_at', anchor.anchored_at);
  const checkpointedAt = finiteTime('recovery_checkpointed_at', checkpoint.checkpointed_at);

  const checks = {
    anchor_chain_verified: chain.verified === true,
    latest_generation_matches: chain.latest_generation === manifest.generation && anchor.generation === manifest.generation,
    latest_manifest_matches: chain.latest_manifest_sha256 === manifest.manifest_sha256 && anchor.manifest_sha256 === manifest.manifest_sha256,
    anchor_head_matches: chain.head_sha256 === anchor.record_sha256,
    checkpoint_root_matches: checkpoint.state_root_sha256 === manifest.checkpoint_state_root_sha256 && anchor.checkpoint_state_root_sha256 === checkpoint.state_root_sha256,
    snapshot_restore_verifies: restore.state === 'PASS',
    manifest_fresh: createdAt <= now + 30000 && now - createdAt <= maxAge,
    anchor_fresh: anchoredAt <= now + 30000 && now - anchoredAt <= maxAge,
    checkpoint_fresh: checkpointedAt <= now + 30000 && now - checkpointedAt <= maxAge,
    no_secret_material: manifest.contains_secret_material === false && restore.restored_secret_material === false,
    no_live_activation: restore.activates_live_execution === false,
    no_value_movement: manifest.permits_value_movement === false && anchor.permits_value_movement === false && restore.permits_value_movement === false,
  };

  const state = Object.values(checks).every(Boolean) ? 'PASS' : 'BLOCK';
  const body = {
    schema: 'g-bank-recovery-readiness-audit/v2',
    state,
    generation: manifest.generation,
    manifest_sha256: manifest.manifest_sha256,
    recovery_anchor_head_sha256: chain.head_sha256,
    recovery_anchor_record_sha256: anchor.record_sha256,
    checkpoint_state_root_sha256: checkpoint.state_root_sha256,
    restore_verification_sha256: restore.verification_sha256,
    max_age_ms: maxAge,
    checks,
    grants_external_rights: false,
    activates_live_execution: false,
    permits_value_movement: false,
    audited_at: new Date(now).toISOString(),
  };
  return Object.freeze({ ...body, audit_sha256: sha256(canonicalJson(body)) });
}

module.exports = { assessRecoveryReadiness };
