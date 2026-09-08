require('dotenv').config();

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : null;
}

function canonicalRecord(record) {
  return JSON.stringify({
    version: record.version,
    type: record.type,
    provider: record.provider,
    observed_at: record.observed_at,
    evidence_ref: record.evidence_ref,
    artifact_sha256: record.artifact_sha256
  });
}

const type = String(arg('--type') || '').toUpperCase();
const provider = String(arg('--provider') || 'truelayer').toLowerCase();
const evidenceRef = String(arg('--evidence-ref') || '').trim();
const artifactPath = arg('--artifact');
const confirmed = process.argv.includes('--confirm-evidence');

if (!confirmed) {
  console.error('Refusing to record banking evidence without --confirm-evidence.');
  process.exit(2);
}

if (!['SECRET_ROTATION', 'SANDBOX_VERIFICATION'].includes(type)) {
  console.error('--type must be SECRET_ROTATION or SANDBOX_VERIFICATION.');
  process.exit(2);
}

if (!/^[a-z0-9._-]{2,40}$/.test(provider)) {
  console.error('--provider is invalid.');
  process.exit(2);
}

if (evidenceRef.length < 6 || evidenceRef.length > 300) {
  console.error('--evidence-ref must be a non-secret external reference between 6 and 300 characters.');
  process.exit(2);
}

let artifactSha256 = null;
if (artifactPath) {
  const resolved = path.resolve(artifactPath);
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    console.error('--artifact must point to an existing file.');
    process.exit(2);
  }
  artifactSha256 = crypto.createHash('sha256').update(fs.readFileSync(resolved)).digest('hex');
}

if (type === 'SANDBOX_VERIFICATION' && !artifactSha256) {
  console.error('SANDBOX_VERIFICATION requires --artifact so the provider-readiness output is hash-bound.');
  process.exit(2);
}

const record = {
  version: 1,
  type,
  provider,
  observed_at: new Date().toISOString(),
  evidence_ref: evidenceRef,
  artifact_sha256: artifactSha256
};
record.record_sha256 = crypto.createHash('sha256').update(canonicalRecord(record)).digest('hex');

const outDir = path.resolve(process.cwd(), '.secrets', 'evidence');
fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });

const filename = type === 'SECRET_ROTATION'
  ? 'secret-rotation.json'
  : 'sandbox-verification.json';
const outPath = path.join(outDir, filename);

if (fs.existsSync(outPath) && !process.argv.includes('--force')) {
  console.error('Evidence record already exists. Use --force only after intentionally replacing the underlying evidence.');
  process.exit(2);
}

fs.writeFileSync(outPath, JSON.stringify(record, null, 2) + '\n', { mode: 0o600 });

console.log('Banking evidence record written.');
console.log('Type:', type);
console.log('Provider:', provider);
console.log('Record:', outPath);
console.log('Record SHA-256:', record.record_sha256);
console.log('No payment was created and no value was moved.');
