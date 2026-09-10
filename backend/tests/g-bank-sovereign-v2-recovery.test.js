'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createRecoveryManifest, verifyRecoveryManifest, verifyRecoverySources } = require('../g-bank-sovereign-v2/recovery-manifest');
const { RecoveryAnchorStore } = require('../g-bank-sovereign-v2/recovery-anchor-store');
const { writeRecoverySnapshot, verifySnapshotContents } = require('../g-bank-sovereign-v2/recovery-snapshot');
const { verifyRestoreCandidate, assertNoRollback } = require('../g-bank-sovereign-v2/restore-verifier');
const { assessRecoveryReadiness } = require('../g-bank-sovereign-v2/recovery-readiness-audit');

const H = c => c.repeat(64);
const NOW = Date.parse('2026-09-10T09:15:00.000Z');

function setup() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-recovery-v2-'));
  const state = path.join(root, 'state');
  const executions = path.join(root, 'execution-state');
  const backups = path.join(root, 'backups');
  fs.mkdirSync(state, { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(executions, 'nested'), { recursive: true, mode: 0o700 });
  const accountFile = path.join(state, 'accounts.json');
  fs.writeFileSync(accountFile, '{"account":"ok"}\n', { mode: 0o600 });
  fs.writeFileSync(path.join(executions, '001.json'), '{"status":"done"}\n', { mode: 0o600 });
  fs.writeFileSync(path.join(executions, 'nested', '002.json'), '{"status":"settled"}\n', { mode: 0o600 });
  const checkpoint = Object.freeze({
    schema: 'g-bank-sovereign-state-checkpoint/v2',
    state_root_sha256: H('a'),
    checkpointed_at: new Date(NOW - 1000).toISOString(),
  });
  const items = [
    { label: 'ACCOUNT_REGISTRY', kind: 'FILE', path: accountFile },
    { label: 'EXECUTIONS', kind: 'DIRECTORY', path: executions },
  ];
  const anchors = new RecoveryAnchorStore(path.join(root, 'anchors.jsonl'));
  return { root, state, executions, backups, accountFile, checkpoint, items, anchors };
}

function generationOne(s, now = NOW) {
  const manifest = createRecoveryManifest({ checkpoint: s.checkpoint, items: s.items, generation: 1, now: now - 500 });
  const snapshot = writeRecoverySnapshot({ manifest, destination_root: s.backups });
  const anchor = s.anchors.commit({
    generation: 1,
    manifest_sha256: manifest.manifest_sha256,
    previous_manifest_sha256: null,
    checkpoint_state_root_sha256: s.checkpoint.state_root_sha256,
    evidence_sha256: H('b'),
    now: now - 250,
  });
  return { manifest, snapshot, anchor };
}

(() => {
  const s = setup();
  const { manifest, snapshot, anchor } = generationOne(s);

  assert.equal(verifyRecoveryManifest(manifest), true);
  assert.equal(verifyRecoverySources(manifest).verified, true);
  assert.equal(s.anchors.verify().verified, true);
  assert.equal(s.anchors.verify().latest_generation, 1);
  assert.equal(verifySnapshotContents(manifest, snapshot.path).verified, true);

  const restored = verifyRestoreCandidate({ manifest, anchor, restore_root: snapshot.path, checkpoint: s.checkpoint });
  assert.equal(restored.state, 'PASS');
  assert.equal(restored.restored_secret_material, false);
  assert.equal(restored.activates_live_execution, false);
  assert.equal(restored.permits_value_movement, false);

  const audit = assessRecoveryReadiness({
    manifest,
    anchorStore: s.anchors,
    snapshot_root: snapshot.path,
    checkpoint: s.checkpoint,
    max_age_ms: 60000,
    now: NOW,
  });
  assert.equal(audit.state, 'PASS');
  assert.equal(audit.grants_external_rights, false);
  assert.equal(audit.activates_live_execution, false);
  assert.equal(audit.permits_value_movement, false);
  assert.match(audit.audit_sha256, /^[0-9a-f]{64}$/);

  const secondWrite = writeRecoverySnapshot({ manifest, destination_root: s.backups });
  assert.equal(secondWrite.idempotent, true);
  assert.equal(secondWrite.path, snapshot.path);

  fs.writeFileSync(path.join(snapshot.path, 'ACCOUNT_REGISTRY.state'), 'tampered\n');
  assert.equal(verifySnapshotContents(manifest, snapshot.path).verified, false);
  const tamperedRestore = verifyRestoreCandidate({ manifest, anchor, restore_root: snapshot.path, checkpoint: s.checkpoint });
  assert.equal(tamperedRestore.state, 'BLOCK');
  const blockedAudit = assessRecoveryReadiness({
    manifest,
    anchorStore: s.anchors,
    snapshot_root: snapshot.path,
    checkpoint: s.checkpoint,
    max_age_ms: 60000,
    now: NOW,
  });
  assert.equal(blockedAudit.state, 'BLOCK');
})();

(() => {
  const s = setup();
  const manifest = createRecoveryManifest({ checkpoint: s.checkpoint, items: s.items, generation: 1, now: NOW - 500 });
  fs.appendFileSync(s.accountFile, '{"changed":true}\n');
  assert.equal(verifyRecoverySources(manifest).verified, false);
  assert.throws(() => writeRecoverySnapshot({ manifest, destination_root: s.backups }), /source_changed/);
})();

(() => {
  const s = setup();
  const secretDir = path.join(s.root, 'ordinary-state');
  fs.mkdirSync(secretDir, { mode: 0o700 });
  fs.writeFileSync(path.join(secretDir, 'private-key.pem'), 'do-not-copy', { mode: 0o600 });
  assert.throws(() => createRecoveryManifest({
    checkpoint: s.checkpoint,
    items: [{ label: 'ORDINARY_STATE', kind: 'DIRECTORY', path: secretDir }],
    generation: 1,
    now: NOW,
  }), /secret_entry_forbidden/);

  const explicitlySecret = path.join(s.root, 'credentials.json');
  fs.writeFileSync(explicitlySecret, '{}\n', { mode: 0o600 });
  assert.throws(() => createRecoveryManifest({
    checkpoint: s.checkpoint,
    items: [{ label: 'CREDENTIALS', kind: 'FILE', path: explicitlySecret }],
    generation: 1,
    now: NOW,
  }), /secret_path_forbidden/);
})();

(() => {
  const s = setup();
  const dir = path.join(s.root, 'symlink-state');
  fs.mkdirSync(dir, { mode: 0o700 });
  fs.symlinkSync(s.accountFile, path.join(dir, 'alias.json'));
  assert.throws(() => createRecoveryManifest({
    checkpoint: s.checkpoint,
    items: [{ label: 'SYMLINK_STATE', kind: 'DIRECTORY', path: dir }],
    generation: 1,
    now: NOW,
  }), /symlink_forbidden/);
})();

(() => {
  const s = setup();
  assert.throws(() => createRecoveryManifest({
    checkpoint: s.checkpoint,
    items: [
      { label: 'EXECUTIONS', kind: 'DIRECTORY', path: s.executions },
      { label: 'NESTED_ENTRY', kind: 'FILE', path: path.join(s.executions, '001.json') },
    ],
    generation: 1,
    now: NOW,
  }), /overlapping_source/);

  const manifest = createRecoveryManifest({
    checkpoint: s.checkpoint,
    items: [{ label: 'EXECUTIONS', kind: 'DIRECTORY', path: s.executions }],
    generation: 1,
    now: NOW,
  });
  assert.throws(() => writeRecoverySnapshot({
    manifest,
    destination_root: path.join(s.executions, 'backups'),
  }), /destination_inside_source_forbidden/);
})();

(() => {
  const s = setup();
  const first = generationOne(s);
  fs.writeFileSync(s.accountFile, '{"account":"generation-2"}\n');
  const manifest2 = createRecoveryManifest({
    checkpoint: s.checkpoint,
    items: s.items,
    generation: 2,
    previous_manifest_sha256: first.manifest.manifest_sha256,
    now: NOW + 1000,
  });
  writeRecoverySnapshot({ manifest: manifest2, destination_root: s.backups });
  const anchor2 = s.anchors.commit({
    generation: 2,
    manifest_sha256: manifest2.manifest_sha256,
    previous_manifest_sha256: first.manifest.manifest_sha256,
    checkpoint_state_root_sha256: s.checkpoint.state_root_sha256,
    evidence_sha256: H('c'),
    now: NOW + 1200,
  });
  assert.equal(s.anchors.verify().latest_generation, 2);
  assert.throws(() => assertNoRollback({ candidateManifest: first.manifest, trustedAnchor: anchor2 }), /rollback_generation_denied/);

  const skipManifest = createRecoveryManifest({
    checkpoint: s.checkpoint,
    items: s.items,
    generation: 4,
    previous_manifest_sha256: manifest2.manifest_sha256,
    now: NOW + 2000,
  });
  assert.throws(() => assertNoRollback({ candidateManifest: skipManifest, trustedAnchor: anchor2 }), /intermediate_anchors_required/);
})();

(() => {
  const s = setup();
  const first = generationOne(s, NOW - 120000);
  const stale = assessRecoveryReadiness({
    manifest: first.manifest,
    anchorStore: s.anchors,
    snapshot_root: first.snapshot.path,
    checkpoint: s.checkpoint,
    max_age_ms: 60000,
    now: NOW,
  });
  assert.equal(stale.state, 'BLOCK');
  assert.equal(stale.checks.manifest_fresh, false);
  assert.equal(stale.checks.anchor_fresh, false);
})();

(() => {
  const s = setup();
  generationOne(s);
  const rows = fs.readFileSync(s.anchors.filePath, 'utf8').trim().split('\n').map(JSON.parse);
  rows[0].evidence_sha256 = H('d');
  fs.writeFileSync(s.anchors.filePath, rows.map(JSON.stringify).join('\n') + '\n');
  assert.throws(() => s.anchors.verify(), /record_hash_mismatch/);
})();

console.log('G-BANK sovereign v2 disaster recovery tests: PASS');
