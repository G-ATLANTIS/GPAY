require('dotenv').config();

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const openBanking = require('../backend/routes/openbanking')._test;
const {
  validateEvidenceReceipt,
  validateStoredWebhookReceipt
} = openBanking;

const root = process.cwd();
const reportDir = path.resolve(root, '.secrets', 'go-live');

function nowSafe() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function latestMatching(dir, prefix) {
  if (!fs.existsSync(dir)) return null;
  const files = fs.readdirSync(dir)
    .filter(name => name.startsWith(prefix) && name.endsWith('.json'))
    .map(name => ({
      name,
      path: path.join(dir, name),
      mtimeMs: fs.statSync(path.join(dir, name)).mtimeMs
    }))
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
  return files[0] || null;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function fileExists(value) {
  return Boolean(value) && fs.existsSync(value);
}

function runLocalCommand(command, args) {
  const result = spawnSync(command, args, {
    cwd: root,
    env: process.env,
    encoding: 'utf8'
  });
  return {
    ok: result.status === 0,
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || ''
  };
}

function stage(name, state, detail, evidence = null) {
  return { name, state, detail, evidence };
}

function classify(stages) {
  const byName = Object.fromEntries(stages.map(item => [item.name, item]));

  if (byName.LOCAL_TESTS?.state === 'BLOCKED') {
    return 'BLOCKED_LOCAL';
  }
  if (byName.PROVIDER_READINESS?.state !== 'VERIFIED') {
    return 'READY_FOR_SANDBOX_PROBE';
  }
  if (
    byName.SANDBOX_PAYMENT?.state !== 'VERIFIED' ||
    byName.SANDBOX_RECONCILIATION?.state !== 'VERIFIED'
  ) {
    return 'SANDBOX_PROVIDER_VERIFIED';
  }
  if (byName.REAL_WEBHOOK?.state !== 'VERIFIED') {
    return 'SANDBOX_E2E_PARTIAL';
  }
  if (byName.SECRET_ROTATION?.state !== 'VERIFIED') {
    return 'SANDBOX_E2E_VERIFIED_SECURITY_BLOCKED';
  }
  if (byName.PRODUCTION_CONFIG?.state !== 'VERIFIED') {
    return 'READY_FOR_PRODUCTION_ONBOARDING';
  }
  if (byName.ENV_READINESS?.state !== 'VERIFIED') {
    return 'PRODUCTION_CONFIG_BLOCKED';
  }
  return 'READY_FOR_LIVE_CANARY';
}

function writeReport(report) {
  fs.mkdirSync(reportDir, { recursive: true, mode: 0o700 });
  const file = path.join(reportDir, `go-live-report-${nowSafe()}.json`);
  fs.writeFileSync(file, JSON.stringify(report, null, 2) + '\n', {
    flag: 'wx',
    mode: 0o600
  });
  return file;
}

function validateProviderReadinessArtifact(smokeDir) {
  const latest = latestMatching(smokeDir, 'provider-readiness-');
  if (!latest) return { verified: false, reason: 'No provider-readiness artifact found.' };

  try {
    const body = readJson(latest.path);
    const verified =
      body.environment === 'sandbox' &&
      body.access_token_obtained === true &&
      body.request_signature_accepted === true &&
      body.provider_http_status === 204 &&
      body.payment_created === false &&
      body.value_moved === false &&
      body.verified_value_flow === false;
    return {
      verified,
      reason: verified ? 'TrueLayer sandbox token + request signature accepted.' : 'Artifact does not satisfy the 204 proof contract.',
      artifact: latest.path
    };
  } catch (err) {
    return { verified: false, reason: `Unreadable provider-readiness artifact: ${err.message}` };
  }
}

function validateSandboxPaymentArtifacts(smokeDir) {
  const latest = latestMatching(smokeDir, 'payment-created-');
  if (!latest) return { verified: false, reason: 'No sandbox payment-created artifact found.' };
  try {
    const body = readJson(latest.path);
    const verified =
      body.environment === 'sandbox' &&
      typeof body.payment_id === 'string' &&
      body.authorization_required === true &&
      !('authorization_url' in body) &&
      /^[0-9a-f]{64}$/i.test(String(body.authorization_url_sha256 || ''));
    return {
      verified,
      paymentId: body.payment_id || null,
      reason: verified ? 'Sandbox payment object evidence found without HPP token leakage.' : 'Payment artifact did not satisfy the sandbox contract.',
      artifact: latest.path
    };
  } catch (err) {
    return { verified: false, reason: `Unreadable payment-created artifact: ${err.message}` };
  }
}

function validateReconciliationArtifact(smokeDir, paymentId) {
  if (!paymentId) return { verified: false, reason: 'No sandbox payment ID available.' };
  const latest = latestMatching(smokeDir, `payment-reconcile-${paymentId}-`);
  if (!latest) return { verified: false, reason: 'No reconciliation artifact found for the latest sandbox payment.' };
  try {
    const body = readJson(latest.path);
    const verified =
      body.environment === 'sandbox' &&
      body.payment_id === paymentId &&
      ['BANK_ACCEPTED_NOT_SETTLEMENT_PROVEN', 'FAILED', 'AUTHORIZED', 'AUTHORIZING', 'AUTHORIZATION_REQUIRED']
        .includes(String(body.reconciliation?.state || '')) &&
      body.creditor_settlement_proven === false &&
      body.verified_value_flow === false;
    return {
      verified,
      state: body.reconciliation?.state || null,
      reason: verified ? 'Sandbox provider/payment state reconciled without false settlement promotion.' : 'Reconciliation artifact did not satisfy the fail-closed contract.',
      artifact: latest.path
    };
  } catch (err) {
    return { verified: false, reason: `Unreadable reconciliation artifact: ${err.message}` };
  }
}

function detectRealWebhook(paymentId) {
  if (!paymentId) return { verified: false, reason: 'No payment ID to match webhook evidence.' };
  const base = process.env.G_BANK_WEBHOOK_RECEIPT_DIR || '';
  if (!base) return { verified: false, reason: 'G_BANK_WEBHOOK_RECEIPT_DIR is not configured.' };
  const dir = path.resolve(base, 'sandbox');
  if (!fs.existsSync(dir)) return { verified: false, reason: 'Sandbox webhook receipt directory does not exist.' };

  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith('.json')) continue;
    try {
      const body = readJson(path.join(dir, name));
      validateStoredWebhookReceipt(body);
      if (
        String(body.payment_id || '').toLowerCase() === String(paymentId).toLowerCase() &&
        body.provider === 'truelayer' &&
        body.environment === 'sandbox'
      ) {
        return {
          verified: true,
          reason: 'Durable TrueLayer-signed sandbox webhook receipt found for payment.',
          artifact: path.join(dir, name)
        };
      }
    } catch {
      // Ignore unrelated unreadable files; runtime reconciliation performs the strict store-integrity check.
    }
  }
  return { verified: false, reason: 'No matching durable TrueLayer sandbox webhook receipt found.' };
}

function secretRotationState() {
  const file = process.env.G_BANK_SECRET_ROTATION_RECEIPT_FILE || '';
  const result = validateEvidenceReceipt(
    file,
    'SECRET_ROTATION',
    10 * 365 * 24 * 60 * 60 * 1000
  );
  return result.valid
    ? {
        verified: true,
        reason: 'Secret-rotation evidence passed integrity/freshness validation.',
        artifact: file
      }
    : {
        verified: false,
        reason: `Historical provider secret rotation evidence is missing/invalid: ${result.error || 'unknown'}`
      };
}

function productionConfigState() {
  const rotationEvidence = validateEvidenceReceipt(
    process.env.G_BANK_SECRET_ROTATION_RECEIPT_FILE || '',
    'SECRET_ROTATION',
    10 * 365 * 24 * 60 * 60 * 1000
  );
  const sandboxEvidence = validateEvidenceReceipt(
    process.env.G_BANK_SANDBOX_VERIFICATION_RECEIPT_FILE || '',
    'SANDBOX_VERIFICATION',
    30 * 24 * 60 * 60 * 1000
  );

  const required = {
    live_selected: (process.env.TRUELAYER_ENV || '').toLowerCase() === 'live',
    live_enabled: process.env.G_BANK_ENABLE_LIVE === 'true',
    client_id: Boolean(process.env.TRUELAYER_CLIENT_ID),
    client_secret: Boolean(process.env.TRUELAYER_CLIENT_SECRET),
    signing_kid: Boolean(process.env.TRUELAYER_SIGNING_KID),
    private_key: Boolean(process.env.TRUELAYER_PRIVATE_KEY_B64 || process.env.TRUELAYER_PRIVATE_KEY_PEM),
    approval_secret: (process.env.G_BANK_APPROVAL_SECRET || '').length >= 32,
    allowlist: String(process.env.G_BANK_ALLOWED_BENEFICIARY_IBANS || '').split(',').map(v => v.trim()).filter(Boolean).length > 0,
    webhook_store: Boolean(process.env.G_BANK_WEBHOOK_RECEIPT_DIR),
    intent_store: Boolean(process.env.G_BANK_PAYMENT_INTENT_DIR),
    rotation_receipt: rotationEvidence.valid,
    sandbox_receipt: sandboxEvidence.valid
  };
  return {
    verified: Object.values(required).every(Boolean),
    required,
    reason: Object.values(required).every(Boolean)
      ? 'Production configuration gates are locally present. Live canary still requires explicit human authorization.'
      : 'Production configuration is incomplete or intentionally disabled.'
  };
}

async function maybeRunProbe() {
  if (!process.argv.includes('--run-sandbox-probe')) {
    return { attempted: false, ok: false, detail: 'Not requested.' };
  }
  if ((process.env.TRUELAYER_ENV || 'sandbox').toLowerCase() !== 'sandbox') {
    return { attempted: true, ok: false, detail: 'Probe refused because TRUELAYER_ENV is not sandbox.' };
  }
  if (process.env.G_BANK_ENABLE_LIVE === 'true') {
    return { attempted: true, ok: false, detail: 'Probe refused because live banking is enabled.' };
  }

  const result = runLocalCommand(process.execPath, ['scripts/run-banking-sandbox-smoke.js', 'probe']);
  return {
    attempted: true,
    ok: result.ok,
    detail: result.ok ? 'Sandbox provider probe completed.' : 'Sandbox provider probe failed.',
    stdout: result.stdout,
    stderr: result.stderr
  };
}

async function main() {
  const stages = [];

  const syntax = runLocalCommand('npm', ['run', 'check:banking']);
  const policy = runLocalCommand('npm', ['run', 'test:banking']);
  const smokeTests = runLocalCommand('npm', ['run', 'test:banking:smoke']);
  const envReadiness = runLocalCommand('npm', ['run', 'check:banking:env']);
  const localOk = syntax.ok && policy.ok && smokeTests.ok;
  stages.push(stage(
    'LOCAL_TESTS',
    localOk ? 'VERIFIED' : 'BLOCKED',
    localOk ? 'Syntax, banking policy and smoke-runner tests passed.' : 'One or more local Banking test commands failed.',
    {
      check_banking_exit: syntax.status,
      policy_exit: policy.status,
      smoke_test_exit: smokeTests.status
    }
  ));

  stages.push(stage(
    'ENV_READINESS',
    envReadiness.ok ? 'VERIFIED' : 'PENDING',
    envReadiness.ok
      ? 'Runtime Banking environment passed check:banking:env.'
      : 'Runtime Banking environment is not fully configured yet.',
    {
      exit: envReadiness.status,
      stdout_tail: envReadiness.stdout.split('\n').slice(-12).join('\n'),
      stderr_tail: envReadiness.stderr.split('\n').slice(-12).join('\n')
    }
  ));

  const envBeforeProbe = (process.env.TRUELAYER_ENV || 'sandbox').toLowerCase();
  const sandboxConfigOk =
    envBeforeProbe === 'sandbox' &&
    process.env.G_BANK_ENABLE_LIVE !== 'true' &&
    Boolean(process.env.TRUELAYER_CLIENT_ID) &&
    Boolean(process.env.TRUELAYER_CLIENT_SECRET) &&
    Boolean(process.env.TRUELAYER_SIGNING_KID) &&
    Boolean(process.env.TRUELAYER_PRIVATE_KEY_B64 || process.env.TRUELAYER_PRIVATE_KEY_PEM) &&
    (process.env.G_BANK_OPERATOR_SECRET || '').length >= 32;
  stages.push(stage(
    'SANDBOX_CONFIG',
    sandboxConfigOk ? 'VERIFIED' : 'PENDING',
    sandboxConfigOk
      ? 'Sandbox provider credentials/signing/operator inputs are configured.'
      : 'Sandbox credentials/signing/operator inputs are incomplete or live mode is selected.'
  ));

  const probe = await maybeRunProbe();
  const smokeDir = path.resolve(root, '.secrets', 'smoke');
  const provider = validateProviderReadinessArtifact(smokeDir);
  stages.push(stage(
    'PROVIDER_READINESS',
    provider.verified ? 'VERIFIED' : (probe.attempted ? 'BLOCKED' : 'PENDING'),
    provider.verified ? provider.reason : probe.detail || provider.reason,
    provider.artifact || null
  ));

  const payment = validateSandboxPaymentArtifacts(smokeDir);
  stages.push(stage(
    'SANDBOX_PAYMENT',
    payment.verified ? 'VERIFIED' : 'PENDING',
    payment.reason,
    payment.artifact || null
  ));

  const reconciliation = validateReconciliationArtifact(smokeDir, payment.paymentId);
  stages.push(stage(
    'SANDBOX_RECONCILIATION',
    reconciliation.verified ? 'VERIFIED' : 'PENDING',
    reconciliation.reason,
    reconciliation.artifact || null
  ));

  const webhook = detectRealWebhook(payment.paymentId);
  stages.push(stage(
    'REAL_WEBHOOK',
    webhook.verified ? 'VERIFIED' : 'PENDING',
    webhook.reason,
    webhook.artifact || null
  ));

  const rotation = secretRotationState();
  stages.push(stage(
    'SECRET_ROTATION',
    rotation.verified ? 'VERIFIED' : 'BLOCKED',
    rotation.reason,
    rotation.artifact || null
  ));

  const production = productionConfigState();
  stages.push(stage(
    'PRODUCTION_CONFIG',
    production.verified ? 'VERIFIED' : 'PENDING',
    production.reason,
    production.required
  ));

  const readiness = classify(stages);
  const report = {
    version: 1,
    generated_at: new Date().toISOString(),
    command: 'banking:go-live',
    readiness,
    live_banking: false,
    live_payment_executed_by_command: false,
    verified_value_flow: false,
    stages,
    next_action: {
      BLOCKED_LOCAL: 'Fix local configuration/tests first.',
      READY_FOR_SANDBOX_PROBE: 'Complete TrueLayer sandbox credentials/public key/KID, then rerun with --run-sandbox-probe.',
      SANDBOX_PROVIDER_VERIFIED: 'Run the sandbox create/HPP/status/reconcile flow.',
      SANDBOX_E2E_PARTIAL: 'Route the registered TrueLayer sandbox webhook URI to G-Bank and obtain a real signed webhook receipt.',
      SANDBOX_E2E_VERIFIED_SECURITY_BLOCKED: 'Resolve historical provider credential rotation/revocation and preserve evidence.',
      READY_FOR_PRODUCTION_ONBOARDING: 'Configure TrueLayer production credentials, HTTPS endpoints and live release gates.',
      PRODUCTION_CONFIG_BLOCKED: 'Fix the failing runtime environment/readiness checks before any live canary.',
      READY_FOR_LIVE_CANARY: 'Perform a separately authorized tiny production canary and independently verify settlement before promoting live.'
    }[readiness]
  };

  const reportFile = writeReport(report);

  console.log('');
  console.log('=== G-BANK GO-LIVE REPORT ===');
  for (const item of stages) {
    console.log(`${item.state.padEnd(8)} ${item.name} — ${item.detail}`);
  }
  console.log('');
  console.log('READINESS:', readiness);
  console.log('LIVE_BANKING: FALSE');
  console.log('VERIFIED_VALUE_FLOW: FALSE');
  console.log('NEXT:', report.next_action);
  console.log('REPORT:', reportFile);

  process.exitCode = readiness === 'BLOCKED_LOCAL' ? 2 : 0;
}

if (require.main === module) {
  main().catch(err => {
    console.error('G-Bank go-live orchestrator failed:', err.message || err);
    process.exit(2);
  });
}

module.exports = {
  latestMatching,
  validateProviderReadinessArtifact,
  validateSandboxPaymentArtifacts,
  validateReconciliationArtifact,
  detectRealWebhook,
  secretRotationState,
  productionConfigState,
  classify
};
