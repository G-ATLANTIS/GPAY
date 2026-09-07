require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function privateKeyPem() {
  if (process.env.TRUELAYER_PRIVATE_KEY_B64) {
    return Buffer.from(process.env.TRUELAYER_PRIVATE_KEY_B64, 'base64').toString('utf8');
  }
  if (process.env.TRUELAYER_PRIVATE_KEY_PEM) {
    return process.env.TRUELAYER_PRIVATE_KEY_PEM.replace(/\\n/g, '\n');
  }
  return '';
}

function resultLine(name, status, detail) {
  const suffix = detail ? ` — ${detail}` : '';
  console.log(`${status.padEnd(5)} ${name}${suffix}`);
}

function main() {
  const env = (process.env.TRUELAYER_ENV || 'sandbox').toLowerCase();
  const live = env === 'live';
  const errors = [];
  const warnings = [];

  if (!['sandbox', 'live'].includes(env)) errors.push('TRUELAYER_ENV must be sandbox or live.');

  const clientId = process.env.TRUELAYER_CLIENT_ID || '';
  const clientSecret = process.env.TRUELAYER_CLIENT_SECRET || '';
  const signingKid = process.env.TRUELAYER_SIGNING_KID || '';
  const returnUri = process.env.TRUELAYER_RETURN_URI || '';
  const keyPem = privateKeyPem();
  const maxEur = Number(process.env.G_BANK_MAX_PAYMENT_EUR || '0');
  const liveEnabled = process.env.G_BANK_ENABLE_LIVE === 'true';
  const probeEnabled = process.env.G_BANK_ENABLE_PROVIDER_PROBE === 'true';
  const webhookReceiptDir = process.env.G_BANK_WEBHOOK_RECEIPT_DIR || '';
  const operatorSecret = process.env.G_BANK_OPERATOR_SECRET || '';

  resultLine('environment', 'OK', env);

  if (operatorSecret.length < 32) {
    resultLine('G_BANK_OPERATOR_SECRET', 'FAIL', 'minimum 32 characters');
    errors.push('G_BANK_OPERATOR_SECRET must be at least 32 characters.');
  } else {
    resultLine('G_BANK_OPERATOR_SECRET', 'OK');
  }

  for (const [name, value] of [
    ['TRUELAYER_CLIENT_ID', clientId],
    ['TRUELAYER_CLIENT_SECRET', clientSecret],
    ['TRUELAYER_SIGNING_KID', signingKid],
    ['TRUELAYER_RETURN_URI', returnUri],
    ['TrueLayer private key', keyPem]
  ]) {
    if (value) resultLine(name, 'OK');
    else {
      resultLine(name, 'MISS');
      errors.push(`${name} is missing.`);
    }
  }

  if (keyPem) {
    try {
      const key = crypto.createPrivateKey(keyPem);
      const typeOk = key.asymmetricKeyType === 'ec';
      const curveOk = key.asymmetricKeyDetails?.namedCurve === 'secp521r1';
      if (!typeOk || !curveOk) {
        resultLine('signing key curve', 'FAIL', `${key.asymmetricKeyType || 'unknown'}/${key.asymmetricKeyDetails?.namedCurve || 'unknown'}`);
        errors.push('TrueLayer signing key must be EC P-521 / secp521r1.');
      } else {
        resultLine('signing key curve', 'OK', 'secp521r1');
      }
    } catch {
      resultLine('signing key parse', 'FAIL');
      errors.push('TrueLayer private key cannot be parsed.');
    }
  }

  if (!Number.isFinite(maxEur) || maxEur <= 0) {
    resultLine('G_BANK_MAX_PAYMENT_EUR', 'FAIL');
    errors.push('G_BANK_MAX_PAYMENT_EUR must be a positive finite number.');
  } else {
    resultLine('G_BANK_MAX_PAYMENT_EUR', 'OK', String(maxEur));
  }

  if (returnUri) {
    try {
      const url = new URL(returnUri);
      if (live && url.protocol !== 'https:') {
        resultLine('live return URI', 'FAIL', 'HTTPS required');
        errors.push('Live TRUELAYER_RETURN_URI must use HTTPS.');
      } else if (!live && !['https:', 'http:'].includes(url.protocol)) {
        resultLine('sandbox return URI', 'FAIL');
        errors.push('Sandbox TRUELAYER_RETURN_URI must use HTTP or HTTPS.');
      } else {
        resultLine('return URI scheme', 'OK', url.protocol);
      }
    } catch {
      resultLine('return URI parse', 'FAIL');
      errors.push('TRUELAYER_RETURN_URI is not a valid URL.');
    }
  }

  if (live) {
    if (!liveEnabled) {
      resultLine('live execution gate', 'SAFE', 'disabled');
      warnings.push('Live environment selected but G_BANK_ENABLE_LIVE is not true.');
    } else {
      resultLine('live execution gate', 'OPEN');
      if (!(process.env.G_BANK_APPROVAL_SECRET || '')) {
        errors.push('G_BANK_APPROVAL_SECRET is required when live execution is enabled.');
      }
      for (const [name, value] of [
        ['G_BANK_SECRET_ROTATION_RECEIPT_FILE', process.env.G_BANK_SECRET_ROTATION_RECEIPT_FILE || ''],
        ['G_BANK_SANDBOX_VERIFICATION_RECEIPT_FILE', process.env.G_BANK_SANDBOX_VERIFICATION_RECEIPT_FILE || '']
      ]) {
        if (!value || !fs.existsSync(value)) {
          errors.push(`${name} must point to an existing evidence record when live execution is enabled.`);
        }
      }
      const ibans = String(process.env.G_BANK_ALLOWED_BENEFICIARY_IBANS || '').split(',').map(v => v.trim()).filter(Boolean);
      if (ibans.length === 0) errors.push('At least one G_BANK_ALLOWED_BENEFICIARY_IBANS entry is required when live execution is enabled.');
      if (!webhookReceiptDir) {
        errors.push('G_BANK_WEBHOOK_RECEIPT_DIR must be explicitly configured when live execution is enabled.');
      }
    }
  } else {
    resultLine('live execution gate', 'SAFE', liveEnabled ? 'ignored in sandbox' : 'disabled');
  }

  if (webhookReceiptDir) {
    try {
      const environmentDir = path.resolve(webhookReceiptDir, env);
      fs.mkdirSync(environmentDir, { recursive: true, mode: 0o700 });
      const probePath = path.join(environmentDir, `.readiness-${process.pid}-${Date.now()}`);
      const fd = fs.openSync(probePath, 'wx', 0o600);
      try {
        fs.writeFileSync(fd, 'g-bank-webhook-receipt-store-readiness\n', 'utf8');
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.unlinkSync(probePath);
      resultLine('webhook receipt store', 'OK', environmentDir);
      if (live && !path.isAbsolute(webhookReceiptDir)) {
        warnings.push('Live webhook receipt directory is relative; independently confirm the underlying filesystem survives process/container restarts.');
      }
    } catch {
      resultLine('webhook receipt store', 'FAIL');
      errors.push('G_BANK_WEBHOOK_RECEIPT_DIR is not atomically writable.');
    }
  } else if (!live) {
    resultLine('webhook receipt store', 'SAFE', 'not configured; sandbox default may be used by runtime');
  }

  if (probeEnabled && (process.env.G_BANK_PROVIDER_PROBE_SECRET || '').length < 32) {
    resultLine('provider readiness probe', 'FAIL', 'authorization secret missing/too short');
    errors.push('G_BANK_PROVIDER_PROBE_SECRET must be at least 32 characters when the provider probe is enabled.');
  } else {
    resultLine('provider readiness probe', probeEnabled ? 'OPEN' : 'SAFE', probeEnabled ? 'non-payment probe enabled and authenticated' : 'disabled');
  }

  console.log('');
  if (errors.length) {
    console.error(`Banking readiness: BLOCKED (${errors.length} blocker(s))`);
    for (const error of errors) console.error(`- ${error}`);
    process.exit(2);
  }

  console.log('Banking readiness: CONFIGURED');
  if (warnings.length) {
    for (const warning of warnings) console.log(`- warning: ${warning}`);
  }
  console.log('No payment was created and no value was moved.');
}

main();
