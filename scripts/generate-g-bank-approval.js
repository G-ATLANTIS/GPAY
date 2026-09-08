require('dotenv').config();

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : null;
}

function validIban(iban) {
  const compact = String(iban || '').replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(compact)) return false;
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const fragment = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of fragment) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}

const confirmed = process.argv.includes('--confirm-approval');
if (!confirmed) {
  console.error('Refusing to generate a payment approval token without --confirm-approval.');
  process.exit(2);
}

const secret = process.env.G_BANK_APPROVAL_SECRET || '';
if (secret.length < 32) {
  console.error('G_BANK_APPROVAL_SECRET must be present and at least 32 characters.');
  process.exit(2);
}

const idempotencyKey = arg('--idempotency-key');
const amount = arg('--amount-eur');
const rawIban = arg('--iban');
const reference = arg('--reference');

if (!/^[0-9a-f-]{36}$/i.test(String(idempotencyKey || ''))) {
  console.error('A UUID-like --idempotency-key is required.');
  process.exit(2);
}

if (!/^\d+(?:\.\d{1,2})?$/.test(String(amount || ''))) {
  console.error('--amount-eur must be a positive EUR amount with at most two decimals.');
  process.exit(2);
}

const amountInMinor = Math.round(Number(amount) * 100);
if (!Number.isSafeInteger(amountInMinor) || amountInMinor <= 0) {
  console.error('--amount-eur is outside the supported range.');
  process.exit(2);
}

const iban = String(rawIban || '').replace(/\s+/g, '').toUpperCase();
if (!validIban(iban)) {
  console.error('--iban must pass IBAN checksum validation.');
  process.exit(2);
}

if (!reference) {
  console.error('--reference is required.');
  process.exit(2);
}

const allowed = String(process.env.G_BANK_ALLOWED_BENEFICIARY_IBANS || '')
  .split(',')
  .map(v => v.replace(/\s+/g, '').toUpperCase())
  .filter(Boolean);

if (!allowed.includes(iban)) {
  console.error('IBAN is not present in G_BANK_ALLOWED_BENEFICIARY_IBANS.');
  process.exit(2);
}

const maxEur = Number(process.env.G_BANK_MAX_PAYMENT_EUR || '0');
if (!Number.isFinite(maxEur) || maxEur <= 0 || amountInMinor > Math.round(maxEur * 100)) {
  console.error('Amount exceeds G_BANK_MAX_PAYMENT_EUR or the limit is invalid.');
  process.exit(2);
}

const message = [idempotencyKey, String(amountInMinor), iban, String(reference)].join('|');
const token = crypto.createHmac('sha256', secret).update(message).digest('hex');

const outDir = path.resolve(process.cwd(), '.secrets', 'approvals');
fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
const safeId = idempotencyKey.toLowerCase();
const outPath = path.join(outDir, `${safeId}.approval`);

if (fs.existsSync(outPath)) {
  console.error('Refusing to overwrite an existing approval file.');
  process.exit(2);
}

fs.writeFileSync(outPath, token + '\n', { mode: 0o600 });

console.log('Bound G-Bank approval token generated.');
console.log('Approval file:', outPath);
console.log('Intent binding:');
console.log('- idempotency key:', idempotencyKey);
console.log('- amount in minor:', amountInMinor);
console.log('- IBAN:', iban);
console.log('- reference:', reference);
console.log('No network request was made and no payment was created.');
