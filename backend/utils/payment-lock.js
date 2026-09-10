const fs = require('fs');
const path = require('path');

const STATE_DIR = process.env.GPAY_STATE_DIR || path.join(process.cwd(), 'state');
const LOCK_DIR = path.join(STATE_DIR, 'locks');

function sanitize(value) {
  return String(value).replace(/[^a-zA-Z0-9._-]/g, '_');
}

function acquirePaymentLock(provider, providerPaymentId) {
  fs.mkdirSync(LOCK_DIR, { recursive: true });
  const lockPath = path.join(LOCK_DIR, `${sanitize(provider)}-${sanitize(providerPaymentId)}.lock`);
  try {
    const fd = fs.openSync(lockPath, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, acquiredAt: new Date().toISOString() }));
    fs.closeSync(fd);
    return {
      acquired: true,
      release() {
        try { fs.unlinkSync(lockPath); } catch (err) { if (err.code !== 'ENOENT') throw err; }
      },
    };
  } catch (err) {
    if (err.code === 'EEXIST') return { acquired: false, release() {} };
    throw err;
  }
}

module.exports = { acquirePaymentLock };
