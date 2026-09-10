'use strict';

const fs = require('node:fs');
const path = require('node:path');

// Crash-safe persistence primitives for external-value bookkeeping.
//
// A completed state transition (idempotency finalize, sequence commit) must not
// be silently lost by a crash between write() and the data reaching stable
// storage. The pattern is: write a temp file -> fsync the file -> atomically
// rename over the target -> fsync the containing directory so the rename itself
// is durable.

function fsyncDir(dir) {
  let fd;
  try {
    fd = fs.openSync(dir, 'r');
    fs.fsyncSync(fd);
  } catch {
    // Directory fsync is not portable everywhere (some platforms reject it).
    // The file fsync above is the mandatory guarantee; this is best-effort.
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        /* ignore */
      }
    }
  }
}

// Atomically replace `file` with `data`. Safe to call when `file` already
// exists.
function durableReplaceFileSync(file, data, { mode = 0o600 } = {}) {
  const dir = path.dirname(file);
  const tmp = path.join(
    dir,
    `.${path.basename(file)}.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}.tmp`,
  );
  const fd = fs.openSync(tmp, 'wx', mode);
  try {
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, file);
  fsyncDir(dir);
}

// Create `file` exclusively (O_EXCL). Throws EEXIST if it already exists — the
// caller uses that as the "someone else owns this" signal. On success the bytes
// and the directory entry are both fsynced before returning.
function durableCreateFileSync(file, data, { mode = 0o600 } = {}) {
  const fd = fs.openSync(file, 'wx', mode);
  try {
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fsyncDir(path.dirname(file));
}

module.exports = { fsyncDir, durableReplaceFileSync, durableCreateFileSync };
