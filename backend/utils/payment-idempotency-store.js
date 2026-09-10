const fs = require('fs');
const path = require('path');

const STORE_DIR = process.env.GPAY_STATE_DIR || path.join(process.cwd(), 'state');
const STORE_FILE = path.join(STORE_DIR, 'processed-payments.json');

function ensureStore() {
  fs.mkdirSync(STORE_DIR, { recursive: true });
  if (!fs.existsSync(STORE_FILE)) {
    fs.writeFileSync(STORE_FILE, JSON.stringify({ processed: {} }, null, 2));
  }
}

function readStore() {
  ensureStore();
  return JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
}

function atomicWrite(store) {
  ensureStore();
  const tmp = `${STORE_FILE}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(store, null, 2), { flag: 'wx' });
  fs.renameSync(tmp, STORE_FILE);
}

function getProcessed(provider, providerPaymentId) {
  const store = readStore();
  return store.processed[`${provider}:${providerPaymentId}`] || null;
}

function recordProcessed(provider, providerPaymentId, receipt) {
  const store = readStore();
  const key = `${provider}:${providerPaymentId}`;
  if (store.processed[key]) return { created: false, record: store.processed[key] };
  store.processed[key] = receipt;
  atomicWrite(store);
  return { created: true, record: receipt };
}

module.exports = { getProcessed, recordProcessed };
