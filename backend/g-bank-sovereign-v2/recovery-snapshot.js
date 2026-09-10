'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { verifyRecoveryManifest, verifyRecoverySources, assertSafeSourcePath, assertSafeRelativePath, hashDirectory } = require('./recovery-manifest');
const { sha256 } = require('./canonical');

function fsyncFile(file) {
  const fd = fs.openSync(file, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function fsyncDirectory(dir) {
  const fd = fs.openSync(dir, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function isWithin(parent, child) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function copyFileVerified(source, destination) {
  const stat = fs.lstatSync(source);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('recovery_snapshot_source_file_invalid');
  fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
  fs.chmodSync(destination, 0o600);
  fsyncFile(destination);
}

function copyDirectoryVerified(source, destination, relativeBase = '') {
  const stat = fs.lstatSync(source);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('recovery_snapshot_source_directory_invalid');
  fs.mkdirSync(destination, { mode: 0o700 });
  for (const entry of fs.readdirSync(source, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const relative = assertSafeRelativePath(path.posix.join(relativeBase, entry.name));
    const src = path.join(source, entry.name);
    const dst = path.join(destination, entry.name);
    const lst = fs.lstatSync(src);
    if (lst.isSymbolicLink()) throw new Error('recovery_snapshot_symlink_forbidden');
    if (lst.isDirectory()) copyDirectoryVerified(src, dst, relative);
    else if (lst.isFile()) copyFileVerified(src, dst);
    else throw new Error('recovery_snapshot_unsupported_entry');
  }
  fsyncDirectory(destination);
}

function verifySnapshotContents(manifest, snapshotRoot) {
  verifyRecoveryManifest(manifest);
  const root = path.resolve(snapshotRoot);
  const checks = [];
  for (const item of manifest.items) {
    const target = path.join(root, item.kind === 'DIRECTORY' ? item.label : `${item.label}.state`);
    if (!fs.existsSync(target)) {
      checks.push({ label: item.label, present: false, hash_match: false, size_match: false });
      continue;
    }
    const stat = fs.lstatSync(target);
    if (stat.isSymbolicLink()) throw new Error('recovery_snapshot_symlink_forbidden');
    let currentHash;
    let currentSize;
    if (item.kind === 'FILE') {
      if (!stat.isFile()) throw new Error('recovery_snapshot_item_kind_mismatch');
      currentHash = sha256(fs.readFileSync(target));
      currentSize = stat.size;
    } else {
      if (!stat.isDirectory()) throw new Error('recovery_snapshot_item_kind_mismatch');
      const directory = hashDirectory(target);
      currentHash = directory.root_sha256;
      currentSize = directory.rows.reduce((sum, row) => sum + row.size_bytes, 0);
    }
    checks.push({ label: item.label, present: true, hash_match: currentHash === item.content_sha256, size_match: currentSize === item.size_bytes });
  }
  return Object.freeze({
    verified: checks.every(check => check.present && check.hash_match && check.size_match),
    checks: Object.freeze(checks.map(check => Object.freeze(check))),
  });
}

function writeRecoverySnapshot({ manifest, destination_root }) {
  verifyRecoveryManifest(manifest);
  const sourceVerification = verifyRecoverySources(manifest);
  if (!sourceVerification.verified) throw new Error('recovery_snapshot_source_changed');

  const destinationRoot = assertSafeSourcePath(destination_root);
  for (const item of manifest.items) {
    const source = assertSafeSourcePath(item.source_path);
    if (isWithin(source, destinationRoot)) throw new Error('recovery_snapshot_destination_inside_source_forbidden');
  }

  fs.mkdirSync(destinationRoot, { recursive: true, mode: 0o700 });
  const finalName = `generation-${String(manifest.generation).padStart(8, '0')}-${manifest.manifest_sha256.slice(0, 16)}`;
  const finalPath = path.join(destinationRoot, finalName);
  if (fs.existsSync(finalPath)) {
    const manifestPath = path.join(finalPath, 'manifest.json');
    if (!fs.existsSync(manifestPath)) throw new Error('recovery_snapshot_destination_conflict');
    const existing = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    verifyRecoveryManifest(existing);
    if (existing.manifest_sha256 !== manifest.manifest_sha256) throw new Error('recovery_snapshot_destination_conflict');
    const existingCheck = verifySnapshotContents(manifest, finalPath);
    if (!existingCheck.verified) throw new Error('recovery_snapshot_existing_bytes_invalid');
    return Object.freeze({ path: finalPath, idempotent: true, manifest_sha256: manifest.manifest_sha256 });
  }

  const tempPath = `${finalPath}.tmp-${process.pid}-${Date.now()}`;
  fs.mkdirSync(tempPath, { mode: 0o700 });
  try {
    for (const item of manifest.items) {
      const source = assertSafeSourcePath(item.source_path);
      const destination = path.join(tempPath, item.kind === 'DIRECTORY' ? item.label : `${item.label}.state`);
      if (item.kind === 'FILE') copyFileVerified(source, destination);
      else if (item.kind === 'DIRECTORY') copyDirectoryVerified(source, destination);
      else throw new Error('recovery_snapshot_manifest_kind_invalid');
    }

    const copied = verifySnapshotContents(manifest, tempPath);
    if (!copied.verified) throw new Error('recovery_snapshot_copy_verification_failed');

    const sourceRecheck = verifyRecoverySources(manifest);
    if (!sourceRecheck.verified) throw new Error('recovery_snapshot_source_changed_during_copy');

    const manifestPath = path.join(tempPath, 'manifest.json');
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o400 });
    fsyncFile(manifestPath);
    fsyncDirectory(tempPath);
    fs.renameSync(tempPath, finalPath);
    fsyncDirectory(destinationRoot);

    const finalCheck = verifySnapshotContents(manifest, finalPath);
    if (!finalCheck.verified) throw new Error('recovery_snapshot_final_verification_failed');
    return Object.freeze({ path: finalPath, idempotent: false, manifest_sha256: manifest.manifest_sha256 });
  } catch (err) {
    try { fs.rmSync(tempPath, { recursive: true, force: true }); } catch {}
    throw err;
  }
}

module.exports = { writeRecoverySnapshot, copyDirectoryVerified, verifySnapshotContents };
