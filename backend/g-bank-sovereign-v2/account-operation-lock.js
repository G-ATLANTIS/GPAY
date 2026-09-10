'use strict';

const fs = require('node:fs');

function withAccountOperationLock(accounts, fn) {
  if (!accounts?.filePath) throw new Error('account_registry_lock_binding_missing');
  const lockPath = `${accounts.filePath}.operations.lock`;
  let fd;
  try {
    fd = fs.openSync(lockPath, 'wx', 0o600);
  } catch (err) {
    if (err.code === 'EEXIST') throw new Error('account_operation_busy');
    throw err;
  }
  try {
    return fn();
  } finally {
    try { fs.closeSync(fd); } catch {}
    try { fs.unlinkSync(lockPath); } catch {}
  }
}

module.exports = { withAccountOperationLock };
