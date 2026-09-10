const { URL } = require('url');

const REQUIRED_RUNTIME_ENV = ['MOLLIE_API_KEY', 'GPAY_PUBLIC_BASE_URL'];

function nonEmpty(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function classifyMollieKey(value) {
  if (!nonEmpty(value)) return 'missing';
  const v = value.trim();
  if (v.startsWith('live_')) return 'live';
  if (v.startsWith('test_')) return 'test';
  return 'unknown';
}

function validatePublicBaseUrl(value) {
  if (!nonEmpty(value)) return { ok: false, reason: 'missing' };
  try {
    const parsed = new URL(value.trim());
    if (parsed.protocol !== 'https:') return { ok: false, reason: 'https_required' };
    if (!parsed.hostname) return { ok: false, reason: 'hostname_required' };
    if (['localhost', '127.0.0.1', '::1'].includes(parsed.hostname)) {
      return { ok: false, reason: 'public_hostname_required' };
    }
    return { ok: true, origin: parsed.origin };
  } catch {
    return { ok: false, reason: 'invalid_url' };
  }
}

function runProductionPreflight(env = process.env) {
  const checks = [];

  for (const name of REQUIRED_RUNTIME_ENV) {
    checks.push({ name, ok: nonEmpty(env[name]), status: nonEmpty(env[name]) ? 'present' : 'missing' });
  }

  const mollieMode = classifyMollieKey(env.MOLLIE_API_KEY);
  checks.push({
    name: 'MOLLIE_API_KEY_MODE',
    ok: mollieMode === 'live',
    status: mollieMode,
  });

  const publicUrl = validatePublicBaseUrl(env.GPAY_PUBLIC_BASE_URL);
  checks.push({
    name: 'GPAY_PUBLIC_BASE_URL_POLICY',
    ok: publicUrl.ok,
    status: publicUrl.ok ? 'public_https' : publicUrl.reason,
  });

  // GCOIN remains intent-only in this branch. Production payment readiness must never
  // imply authorization to sign or broadcast an Ethereum transaction.
  checks.push({
    name: 'GCOIN_EXTERNAL_EXECUTION',
    ok: true,
    status: 'disabled_intent_only',
    broadcast: false,
    signerRequired: false,
  });

  const readyForLivePaymentCreation = checks
    .filter((check) => check.name !== 'GCOIN_EXTERNAL_EXECUTION')
    .every((check) => check.ok);

  return {
    schemaVersion: '1.0.0',
    readyForLivePaymentCreation,
    externalExecutionPerformed: false,
    livePaymentCreated: false,
    gcoinSettlementExecution: 'not_attempted',
    checks,
  };
}

if (require.main === module) {
  const result = runProductionPreflight(process.env);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.readyForLivePaymentCreation ? 0 : 2;
}

module.exports = {
  REQUIRED_RUNTIME_ENV,
  classifyMollieKey,
  validatePublicBaseUrl,
  runProductionPreflight,
};
