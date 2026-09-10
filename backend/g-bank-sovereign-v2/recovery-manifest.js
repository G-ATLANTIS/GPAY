'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');

const SECRET_PATTERN = /(^|[\/._-])(secret|secrets|private[-_]?key|credential|credentials|token|tokens|password|passwd|api[-_]?key)([\/._-]|$)/i;

function assertSafeSourcePath(value) {
  const resolved = path.resolve(String(value || ''));
  if (!resolved || resolved === path.parse(resolved).root) throw new Error('recovery_source_path_invalid');
  if (SECRET_PATTERN.test(resolved)) throw new Error('recovery_secret_path_forbidden');
  return resolved;
}

function assertSafeRelativePath(value) {
  const relative = String(value || '').replace(/\\/g, '/');
  if (!relative || relative.startsWith('/') || relative.includes('../') || relative === '..') throw new Error('recovery_relative_path_invalid');
  if (SECRET_PATTERN.test(relative)) throw new Error('recovery_secret_entry_forbidden');
  return relative;
}

function safeLstat(target, missingError) {
  if (!fs.existsSync(target)) throw new Error(missingError);
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink()) throw new Error('recovery_symlink_forbidden');
  return stat;
}

function hashFile(filePath) {
  const stat = safeLstat(filePath, 'recovery_file_missing');
  if (!stat.isFile()) throw new Error('recovery_file_missing');
  return sha256(fs.readFileSync(filePath));
}

function hashDirectory(dirPath) {
  const rootStat = safeLstat(dirPath, 'recovery_directory_missing');
  if (!rootStat.isDirectory()) throw new Error('recovery_directory_missing');
  const rows = [];
  function walk(current, relativeBase = '') {
    const entries = fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute = path.join(current, entry.name);
      const relative = assertSafeRelativePath(path.posix.join(relativeBase, entry.name));
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) throw new Error('recovery_symlink_forbidden');
      if (stat.isDirectory()) walk(absolute, relative);
      else if (stat.isFile()) rows.push({ relative_path: relative, sha256: hashFile(absolute), size_bytes: stat.size });
      else throw new Error('recovery_unsupported_filesystem_entry');
    }
  }
  walk(dirPath);
  return Object.freeze({ rows: Object.freeze(rows), root_sha256: sha256(canonicalJson(rows)) });
}

function validateDirectoryEntries(entries) {
  if (!Array.isArray(entries)) throw new Error('recovery_manifest_directory_entries_invalid');
  const paths = new Set();
  let previous = null;
  for (const row of entries) {
    const relative = assertSafeRelativePath(row?.relative_path);
    if (paths.has(relative)) throw new Error('recovery_manifest_duplicate_directory_entry');
    if (previous !== null && relative.localeCompare(previous) < 0) throw new Error('recovery_manifest_directory_entries_not_canonical');
    const hash = String(row?.sha256 || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error('recovery_manifest_directory_entry_hash_invalid');
    if (!Number.isSafeInteger(Number(row?.size_bytes)) || Number(row.size_bytes) < 0) throw new Error('recovery_manifest_directory_entry_size_invalid');
    paths.add(relative);
    previous = relative;
  }
  return true;
}

function normalizeItem(item) {
  if (!item || typeof item !== 'object') throw new Error('recovery_manifest_item_invalid');
  const label = String(item.label || '').toUpperCase();
  if (!/^[A-Z0-9_:-]{3,128}$/.test(label)) throw new Error('recovery_manifest_label_invalid');
  const kind = String(item.kind || '').toUpperCase();
  if (!['FILE', 'DIRECTORY'].includes(kind)) throw new Error('recovery_manifest_kind_invalid');
  const source = assertSafeSourcePath(item.path);
  const stat = safeLstat(source, kind === 'FILE' ? 'recovery_file_missing' : 'recovery_directory_missing');
  if (kind === 'FILE') {
    if (!stat.isFile()) throw new Error('recovery_file_missing');
    return Object.freeze({
      label,
      kind,
      source_path: source,
      content_sha256: hashFile(source),
      size_bytes: stat.size,
      directory_entries: null,
    });
  }
  if (!stat.isDirectory()) throw new Error('recovery_directory_missing');
  const directory = hashDirectory(source);
  return Object.freeze({
    label,
    kind,
    source_path: source,
    content_sha256: directory.root_sha256,
    size_bytes: directory.rows.reduce((sum, row) => sum + row.size_bytes, 0),
    directory_entries: directory.rows,
  });
}

function pathsOverlap(a, b) {
  const relAB = path.relative(a, b);
  const relBA = path.relative(b, a);
  const inside = rel => rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
  return inside(relAB) || inside(relBA);
}

function createRecoveryManifest({
  checkpoint,
  items,
  generation,
  previous_manifest_sha256 = null,
  now = Date.now(),
}) {
  if (!checkpoint || checkpoint.schema !== 'g-bank-sovereign-state-checkpoint/v2') throw new Error('recovery_checkpoint_required');
  const stateRoot = String(checkpoint.state_root_sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(stateRoot)) throw new Error('recovery_checkpoint_state_root_invalid');
  const gen = Number(generation);
  if (!Number.isSafeInteger(gen) || gen <= 0) throw new Error('recovery_generation_invalid');
  const previous = previous_manifest_sha256 === null ? null : String(previous_manifest_sha256).toLowerCase();
  if (previous !== null && !/^[0-9a-f]{64}$/.test(previous)) throw new Error('recovery_previous_manifest_hash_invalid');
  if (gen === 1 && previous !== null) throw new Error('recovery_genesis_previous_manifest_forbidden');
  if (gen > 1 && previous === null) throw new Error('recovery_previous_manifest_required');
  if (!Array.isArray(items) || !items.length) throw new Error('recovery_manifest_items_required');
  const normalized = items.map(normalizeItem).sort((a, b) => a.label.localeCompare(b.label));
  const labels = new Set();
  const paths = [];
  for (const item of normalized) {
    if (labels.has(item.label)) throw new Error('recovery_manifest_duplicate_label');
    for (const existing of paths) {
      if (pathsOverlap(existing, item.source_path)) throw new Error('recovery_manifest_overlapping_source');
    }
    labels.add(item.label);
    paths.push(item.source_path);
  }

  const body = {
    schema: 'g-bank-recovery-manifest/v2',
    generation: gen,
    previous_manifest_sha256: previous,
    checkpoint_state_root_sha256: stateRoot,
    checkpointed_at: checkpoint.checkpointed_at || null,
    items: normalized,
    created_at: new Date(now).toISOString(),
    contains_secret_material: false,
    grants_external_rights: false,
    permits_value_movement: false,
  };
  return Object.freeze({ ...body, manifest_sha256: sha256(canonicalJson(body)) });
}

function verifyRecoveryManifest(manifest) {
  if (!manifest || manifest.schema !== 'g-bank-recovery-manifest/v2') throw new Error('recovery_manifest_required');
  const supplied = String(manifest.manifest_sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) throw new Error('recovery_manifest_hash_invalid');
  const { manifest_sha256, ...body } = manifest;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('recovery_manifest_hash_mismatch');
  if (manifest.contains_secret_material !== false || manifest.grants_external_rights !== false || manifest.permits_value_movement !== false) {
    throw new Error('recovery_manifest_boundary_invalid');
  }
  const generation = Number(manifest.generation);
  if (!Number.isSafeInteger(generation) || generation <= 0) throw new Error('recovery_manifest_generation_invalid');
  const previous = manifest.previous_manifest_sha256;
  if (generation === 1 && previous !== null) throw new Error('recovery_manifest_genesis_chain_invalid');
  if (generation > 1 && !/^[0-9a-f]{64}$/i.test(String(previous || ''))) throw new Error('recovery_manifest_previous_hash_invalid');
  if (!/^[0-9a-f]{64}$/i.test(String(manifest.checkpoint_state_root_sha256 || ''))) throw new Error('recovery_manifest_state_root_invalid');
  if (!Array.isArray(manifest.items) || !manifest.items.length) throw new Error('recovery_manifest_items_invalid');
  const labels = new Set();
  const sources = [];
  let previousLabel = null;
  for (const item of manifest.items) {
    const label = String(item?.label || '');
    if (!/^[A-Z0-9_:-]{3,128}$/.test(label)) throw new Error('recovery_manifest_label_invalid');
    if (previousLabel !== null && label.localeCompare(previousLabel) < 0) throw new Error('recovery_manifest_items_not_canonical');
    if (labels.has(label)) throw new Error('recovery_manifest_duplicate_label');
    if (!['FILE', 'DIRECTORY'].includes(item.kind)) throw new Error('recovery_manifest_kind_invalid');
    const source = assertSafeSourcePath(item.source_path);
    for (const existing of sources) {
      if (pathsOverlap(existing, source)) throw new Error('recovery_manifest_overlapping_source');
    }
    if (!/^[0-9a-f]{64}$/i.test(String(item.content_sha256 || ''))) throw new Error('recovery_manifest_content_hash_invalid');
    if (!Number.isSafeInteger(Number(item.size_bytes)) || Number(item.size_bytes) < 0) throw new Error('recovery_manifest_size_invalid');
    if (item.kind === 'FILE' && item.directory_entries !== null) throw new Error('recovery_manifest_file_entries_invalid');
    if (item.kind === 'DIRECTORY') validateDirectoryEntries(item.directory_entries);
    labels.add(label);
    sources.push(source);
    previousLabel = label;
  }
  return true;
}

function verifyRecoverySources(manifest) {
  verifyRecoveryManifest(manifest);
  const checks = [];
  for (const item of manifest.items) {
    const source = assertSafeSourcePath(item.source_path);
    let currentHash;
    let currentSize;
    if (item.kind === 'FILE') {
      currentHash = hashFile(source);
      currentSize = safeLstat(source, 'recovery_file_missing').size;
    } else if (item.kind === 'DIRECTORY') {
      const directory = hashDirectory(source);
      currentHash = directory.root_sha256;
      currentSize = directory.rows.reduce((sum, row) => sum + row.size_bytes, 0);
    } else throw new Error('recovery_manifest_kind_invalid');
    checks.push(Object.freeze({
      label: item.label,
      hash_match: currentHash === item.content_sha256,
      size_match: currentSize === item.size_bytes,
    }));
  }
  return Object.freeze({
    schema: 'g-bank-recovery-source-verification/v2',
    verified: checks.every(check => check.hash_match && check.size_match),
    manifest_sha256: manifest.manifest_sha256,
    checks: Object.freeze(checks),
  });
}

module.exports = {
  createRecoveryManifest,
  verifyRecoveryManifest,
  verifyRecoverySources,
  assertSafeSourcePath,
  assertSafeRelativePath,
  hashDirectory,
};
