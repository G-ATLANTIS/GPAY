'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');
const { verifyRecoveryManifest, assertSafeSourcePath, hashDirectory } = require('./recovery-manifest');
const { verifyRecoveryAnchorRecord } = require('./recovery-anchor-store');

function hashFile(filePath) {
  if (!fs.existsSync(filePath)) throw new Error('restore_file_missing');
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('restore_file_invalid');
  return sha256(fs.readFileSync(filePath));
}

function resolveRestoredPath(root, label, kind) {
  const safeLabel = String(label || '').replace(/[^A-Z0-9_:-]/gi, '_');
  if (!safeLabel) throw new Error('restore_label_invalid');
  return path.join(root, `${safeLabel}${kind === 'DIRECTORY' ? '' : '.state'}`);
}

function verifyRestoreCandidate({ manifest, anchor, restore_root, checkpoint }) {
  verifyRecoveryManifest(manifest);
  verifyRecoveryAnchorRecord(anchor);
  if (anchor.generation !== manifest.generation) throw new Error('restore_generation_anchor_mismatch');
  if (anchor.manifest_sha256 !== manifest.manifest_sha256) throw new Error('restore_manifest_anchor_mismatch');
  if (anchor.previous_manifest_sha256 !== manifest.previous_manifest_sha256) throw new Error('restore_manifest_chain_anchor_mismatch');
  if (anchor.checkpoint_state_root_sha256 !== manifest.checkpoint_state_root_sha256) throw new Error('restore_state_root_anchor_mismatch');
  if (!checkpoint || checkpoint.schema !== 'g-bank-sovereign-state-checkpoint/v2') throw new Error('restore_checkpoint_required');
  if (checkpoint.state_root_sha256 !== manifest.checkpoint_state_root_sha256) throw new Error('restore_checkpoint_state_root_mismatch');

  const root = path.resolve(String(restore_root || ''));
  if (!root || root === path.parse(root).root || !fs.existsSync(root)) throw new Error('restore_root_invalid');
  const rootStat = fs.lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error('restore_root_invalid');
  assertSafeSourcePath(root);
  const checks = [];
  for (const item of manifest.items) {
    const restored = resolveRestoredPath(root, item.label, item.kind);
    if (!fs.existsSync(restored)) {
      checks.push(Object.freeze({ label: item.label, present: false, hash_match: false, size_match: false }));
      continue;
    }
    const stat = fs.lstatSync(restored);
    if (stat.isSymbolicLink()) throw new Error('restore_symlink_forbidden');
    let currentHash;
    let currentSize;
    if (item.kind === 'FILE') {
      if (!stat.isFile()) throw new Error('restore_item_kind_mismatch');
      currentHash = hashFile(restored);
      currentSize = stat.size;
    } else if (item.kind === 'DIRECTORY') {
      if (!stat.isDirectory()) throw new Error('restore_item_kind_mismatch');
      const directory = hashDirectory(restored);
      currentHash = directory.root_sha256;
      currentSize = directory.rows.reduce((sum, row) => sum + row.size_bytes, 0);
    } else throw new Error('restore_manifest_kind_invalid');
    checks.push(Object.freeze({
      label: item.label,
      present: true,
      hash_match: currentHash === item.content_sha256,
      size_match: currentSize === item.size_bytes,
    }));
  }

  const verified = checks.every(check => check.present && check.hash_match && check.size_match);
  const body = {
    schema: 'g-bank-restore-verification/v2',
    state: verified ? 'PASS' : 'BLOCK',
    generation: manifest.generation,
    manifest_sha256: manifest.manifest_sha256,
    checkpoint_state_root_sha256: manifest.checkpoint_state_root_sha256,
    anchor_record_sha256: anchor.record_sha256,
    checks,
    restored_secret_material: false,
    activates_live_execution: false,
    permits_value_movement: false,
  };
  return Object.freeze({ ...body, verification_sha256: sha256(canonicalJson(body)) });
}

function assertNoRollback({ candidateManifest, trustedAnchor }) {
  verifyRecoveryManifest(candidateManifest);
  verifyRecoveryAnchorRecord(trustedAnchor);
  const candidateGeneration = Number(candidateManifest.generation);
  const trustedGeneration = Number(trustedAnchor.generation);
  if (candidateGeneration < trustedGeneration) throw new Error('restore_rollback_generation_denied');
  if (candidateGeneration === trustedGeneration) {
    if (candidateManifest.manifest_sha256 !== trustedAnchor.manifest_sha256) throw new Error('restore_same_generation_root_conflict');
    return true;
  }
  if (candidateGeneration !== trustedGeneration + 1) throw new Error('restore_intermediate_anchors_required');
  if (candidateManifest.previous_manifest_sha256 !== trustedAnchor.manifest_sha256) throw new Error('restore_forward_chain_disconnected');
  return true;
}

module.exports = { verifyRestoreCandidate, assertNoRollback, resolveRestoredPath };
