'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { verifyRecoveryManifest, assertSafeSourcePath } = require('./recovery-manifest');

function fsyncFile(file) {
  const fd = fs.openSync(file, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function copyFileVerified(source, destination) {
  const stat = fs.lstatSync(source);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('recovery_snapshot_source_file_invalid');
  fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
  fs.chmodSync(destination, 0o600);
  fsyncFile(destination);
}

function copyDirectoryVerified(source, destination) {
  const stat = fs.lstatSync(source);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('recovery_snapshot_source_directory_invalid');
  fs.mkdirSync(destination, { mode: 0o700 });
  for (const entry of fs.readdirSync(source, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const src = path.join(source, entry.name);
    const dst = path.join(destination, entry.name);
    const lst = fs.lstatSync(src);
    if (lst.isSymbolicLink()) throw new Error('recovery_snapshot_symlink_forbidden');
    if (lst.isDirectory()) copyDirectoryVerified(src, dst);
    else if (lst.isFile()) copyFileVerified(src, dst);
    else throw new Error('recovery_snapshot_unsupported_entry');
  }
}

function writeRecoverySnapshot({ manifest, destination_root }) {
  verifyRecoveryManifest(manifest);
  const destinationRoot = assertSafeSourcePath(destination_root);
  fs.mkdirSync(destinationRoot, { recursive: true, mode: 0o700 });
  const finalName = `generation-${String(manifest.generation).padStart(8, '0')}-${manifest.manifest_sha256.slice(0, 16)}`;
  const finalPath = path.join(destinationRoot, finalName);
  if (fs.existsSync(finalPath)) {
    const manifestPath = path.join(finalPath, 'manifest.json');
    if (!fs.existsSync(manifestPath)) throw new Error('recovery_snapshot_destination_conflict');
    const existing = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    if (existing.manifest_sha256 !== manifest.manifest_sha256) throw new Error('recovery_snapshot_destination_conflict');
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
    const manifestPath = path.join(tempPath, 'manifest.json');
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o400 });
    fsyncFile(manifestPath);
    fs.renameSync(tempPath, finalPath);
    return Object.freeze({ path: finalPath, idempotent: false, manifest_sha256: manifest.manifest_sha256 });
  } catch (err) {
    try { fs.rmSync(tempPath, { recursive: true, force: true }); } catch {}
    throw err;
  }
}

module.exports = { writeRecoverySnapshot, copyDirectoryVerified };
