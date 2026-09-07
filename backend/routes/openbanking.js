const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('node:fs');
const pathModule = require('node:path');

const router = express.Router();

const webhookJwksCache = new Map();
const WEBHOOK_JWKS_CACHE_TTL_MS = 10 * 60 * 1000;
const WEBHOOK_JWKS_MAX_KEYS = 50;
const WEBHOOK_JWKS_MAX_BYTES = 64 * 1024;

function envMode() {
  return (process.env.TRUELAYER_ENV || 'sandbox').toLowerCase() === 'live' ? 'live' : 'sandbox';
}

function endpoints() {
  const live = envMode() === 'live';
  return {
    live,
    authBase: live ? 'https://auth.truelayer.com' : 'https://auth.truelayer-sandbox.com',
    apiBase: live ? 'https://api.truelayer.com' : 'https://api.truelayer-sandbox.com',
  };
}

function privateKeyPem() {
  if (process.env.TRUELAYER_PRIVATE_KEY_B64) {
    return Buffer.from(process.env.TRUELAYER_PRIVATE_KEY_B64, 'base64').toString('utf8');
  }
  if (process.env.TRUELAYER_PRIVATE_KEY_PEM) {
    return process.env.TRUELAYER_PRIVATE_KEY_PEM.replace(/\\n/g, '\n');
  }
  return '';
}

function requiredConfig() {
  const maxEur = Number(process.env.G_BANK_MAX_PAYMENT_EUR || (envMode() === 'sandbox' ? '100' : '0'));
  const allowedBeneficiaryIbans = String(process.env.G_BANK_ALLOWED_BENEFICIARY_IBANS || '')
    .split(',')
    .map((value) => value.replace(/\s+/g, '').toUpperCase())
    .filter(Boolean);
  return {
    clientId: process.env.TRUELAYER_CLIENT_ID || '',
    clientSecret: process.env.TRUELAYER_CLIENT_SECRET || '',
    signingKid: process.env.TRUELAYER_SIGNING_KID || '',
    privateKey: privateKeyPem(),
    returnUri: process.env.TRUELAYER_RETURN_URI || '',
    webhookPath: process.env.TRUELAYER_WEBHOOK_PATH || '/api/open-banking/webhook',
    webhookReceiptDir: process.env.G_BANK_WEBHOOK_RECEIPT_DIR || '.secrets/runtime/webhook-events',
    webhookReceiptDirExplicit: Boolean(process.env.G_BANK_WEBHOOK_RECEIPT_DIR),
    paymentIntentDir: process.env.G_BANK_PAYMENT_INTENT_DIR || '.secrets/runtime/payment-intents',
    paymentIntentDirExplicit: Boolean(process.env.G_BANK_PAYMENT_INTENT_DIR),
    maxEur,
    liveEnabled: process.env.G_BANK_ENABLE_LIVE === 'true',
    providerProbeEnabled: process.env.G_BANK_ENABLE_PROVIDER_PROBE === 'true',
    providerProbeSecret: process.env.G_BANK_PROVIDER_PROBE_SECRET || '',
    operatorSecret: process.env.G_BANK_OPERATOR_SECRET || '',
    approvalSecret: process.env.G_BANK_APPROVAL_SECRET || '',
    secretRotationReceiptFile: process.env.G_BANK_SECRET_ROTATION_RECEIPT_FILE || '',
    sandboxVerificationReceiptFile: process.env.G_BANK_SANDBOX_VERIFICATION_RECEIPT_FILE || '',
    allowedBeneficiaryIbans
  };
}

function canonicalEvidenceRecord(record) {
  return JSON.stringify({
    version: record.version,
    type: record.type,
    provider: record.provider,
    observed_at: record.observed_at,
    evidence_ref: record.evidence_ref,
    artifact_sha256: record.artifact_sha256 ?? null
  });
}

function validateEvidenceReceipt(filePath, expectedType, maxAgeMs) {
  const result = {
    configured: Boolean(filePath),
    valid: false,
    type: expectedType,
    observed_at: null,
    age_ms: null,
    record_sha256: null,
    error: null
  };

  if (!filePath) {
    result.error = 'missing';
    return result;
  }

  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const record = JSON.parse(raw);

    if (record.version !== 1) throw new Error('unsupported_version');
    if (record.type !== expectedType) throw new Error('type_mismatch');
    if (typeof record.provider !== 'string' || !record.provider) throw new Error('provider_missing');
    if (typeof record.evidence_ref !== 'string' || record.evidence_ref.length < 6) throw new Error('evidence_ref_invalid');
    if (typeof record.record_sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(record.record_sha256)) throw new Error('record_sha256_invalid');

    if (expectedType === 'SANDBOX_VERIFICATION' && !/^[0-9a-f]{64}$/i.test(String(record.artifact_sha256 || ''))) {
      throw new Error('artifact_sha256_required');
    }

    const calculated = crypto.createHash('sha256').update(canonicalEvidenceRecord(record)).digest('hex');
    const supplied = Buffer.from(record.record_sha256.toLowerCase(), 'hex');
    const expected = Buffer.from(calculated, 'hex');
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
      throw new Error('integrity_mismatch');
    }

    const observed = Date.parse(record.observed_at);
    if (!Number.isFinite(observed)) throw new Error('observed_at_invalid');
    const ageMs = Date.now() - observed;
    if (ageMs < -5 * 60 * 1000) throw new Error('observed_at_in_future');
    if (ageMs > maxAgeMs) throw new Error('expired');

    result.valid = true;
    result.observed_at = new Date(observed).toISOString();
    result.age_ms = ageMs;
    result.record_sha256 = calculated;
    return result;
  } catch (err) {
    result.error = err.code === 'ENOENT' ? 'not_found' : String(err.message || err);
    return result;
  }
}

function evidenceStatus() {
  const cfg = requiredConfig();
  return {
    secret_rotation: validateEvidenceReceipt(
      cfg.secretRotationReceiptFile,
      'SECRET_ROTATION',
      10 * 365 * 24 * 60 * 60 * 1000
    ),
    sandbox_verification: validateEvidenceReceipt(
      cfg.sandboxVerificationReceiptFile,
      'SANDBOX_VERIFICATION',
      30 * 24 * 60 * 60 * 1000
    )
  };
}

function expectedWebhookJku() {
  return envMode() === 'live'
    ? 'https://webhooks.truelayer.com/.well-known/jwks'
    : 'https://webhooks.truelayer-sandbox.com/.well-known/jwks';
}

function parseDetachedTlSignature(signature) {
  const parts = String(signature || '').split('.');
  if (parts.length !== 3 || parts[1] !== '' || !parts[0] || !parts[2]) {
    throw new Error('invalid_detached_jws');
  }

  let header;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  } catch {
    throw new Error('invalid_jws_header');
  }

  if (header.alg !== 'ES512') throw new Error('unsupported_header_alg');
  if (header.tl_version !== '2') throw new Error('unsupported_header_tl_version');
  if (!header.kid || typeof header.kid !== 'string') throw new Error('missing_header_kid');
  if (!header.jku || typeof header.jku !== 'string') throw new Error('missing_header_jku');
  if (header.jku !== expectedWebhookJku()) throw new Error('untrusted_header_jku');

  const signedHeaders = String(header.tl_headers || '')
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);

  if (!signedHeaders.some(name => name.toLowerCase() === 'x-tl-webhook-timestamp')) {
    throw new Error('timestamp_header_not_signed');
  }

  return {
    header,
    encodedHeader: parts[0],
    encodedSignature: parts[2],
    signedHeaders
  };
}

function normalizedHeaderLookup(headers, name) {
  const wanted = String(name).toLowerCase();
  for (const [key, value] of Object.entries(headers || {})) {
    if (key.toLowerCase() === wanted) {
      if (Array.isArray(value)) return value.join(',');
      if (value === undefined || value === null) return '';
      return String(value);
    }
  }
  return '';
}

function validateWebhookTimestamp(headers) {
  const raw = normalizedHeaderLookup(headers, 'X-TL-Webhook-Timestamp');
  const parsed = Date.parse(raw);
  if (!Number.isFinite(parsed)) throw new Error('invalid_webhook_timestamp');

  const ageMs = Date.now() - parsed;
  if (ageMs < -5 * 60 * 1000) throw new Error('webhook_timestamp_in_future');

  // TrueLayer retries Payments v3 webhooks for up to 72 hours.
  // Allow that documented window plus one hour of clock/transport tolerance.
  if (ageMs > 73 * 60 * 60 * 1000) throw new Error('webhook_timestamp_expired');

  return { timestamp: new Date(parsed).toISOString(), age_ms: ageMs };
}

function buildWebhookSigningPayload({ method, path, signedHeaders, headers, body }) {
  const orderedHeaders = {};
  for (const name of signedHeaders) {
    const value = normalizedHeaderLookup(headers, name);
    if (!value) throw new Error(`missing_signed_header:${name}`);
    orderedHeaders[name] = value;
  }
  return buildTrueLayerSigningPayload({
    method,
    path,
    headers: orderedHeaders,
    body
  });
}

function verifyWebhookSignature({ signature, method = 'POST', path, headers, rawBody, jwks }) {
  const parsed = parseDetachedTlSignature(signature);
  if (!path || path !== requiredConfig().webhookPath) throw new Error('webhook_path_mismatch');
  if (!Buffer.isBuffer(rawBody)) throw new Error('raw_webhook_body_required');

  const timestamp = validateWebhookTimestamp(headers);
  const body = rawBody.toString('utf8');

  const keys = Array.isArray(jwks?.keys) ? jwks.keys : [];
  const jwk = keys.find(key => key && key.kid === parsed.header.kid);
  if (!jwk) throw new Error('webhook_jwk_not_found');

  let publicKey;
  try {
    publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch {
    throw new Error('invalid_webhook_jwk');
  }

  if (
    publicKey.asymmetricKeyType !== 'ec' ||
    publicKey.asymmetricKeyDetails?.namedCurve !== 'secp521r1'
  ) {
    throw new Error('webhook_jwk_curve_invalid');
  }

  const payload = buildWebhookSigningPayload({
    method: String(method).toUpperCase(),
    path,
    signedHeaders: parsed.signedHeaders,
    headers,
    body
  });

  const signingInput = `${parsed.encodedHeader}.${Buffer.from(payload).toString('base64url')}`;
  const rawSignature = Buffer.from(parsed.encodedSignature, 'base64url');
  if (rawSignature.length !== 132) throw new Error('webhook_signature_length_invalid');

  const valid = crypto.verify(
    'sha512',
    Buffer.from(signingInput, 'utf8'),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    rawSignature
  );

  if (!valid) throw new Error('invalid_webhook_signature');

  return {
    valid: true,
    kid: parsed.header.kid,
    jku: parsed.header.jku,
    environment: parsed.header.jku.includes('truelayer-sandbox.com') ? 'sandbox' : 'live',
    timestamp
  };
}

function validateWebhookJwks(jwks) {
  if (!jwks || !Array.isArray(jwks.keys)) throw new Error('webhook_jwks_invalid');
  if (jwks.keys.length === 0 || jwks.keys.length > WEBHOOK_JWKS_MAX_KEYS) {
    throw new Error('webhook_jwks_key_count_invalid');
  }

  for (const key of jwks.keys) {
    if (!key || typeof key !== 'object') throw new Error('webhook_jwks_key_invalid');
    if (typeof key.kid !== 'string' || !key.kid) throw new Error('webhook_jwks_kid_invalid');
    if (key.kty && key.kty !== 'EC') throw new Error('webhook_jwks_key_type_invalid');
    if (key.crv && key.crv !== 'P-521') throw new Error('webhook_jwks_curve_invalid');
  }

  return jwks;
}

function clearWebhookJwksCache() {
  webhookJwksCache.clear();
}

async function fetchWebhookJwks(httpClient = axios, jku = expectedWebhookJku(), kid = '') {
  if (jku !== expectedWebhookJku()) throw new Error('untrusted_webhook_jwks_url');
  if (!kid) throw new Error('webhook_jwks_kid_required');

  const now = Date.now();
  const cached = webhookJwksCache.get(jku);
  if (
    cached &&
    now - cached.fetched_at <= WEBHOOK_JWKS_CACHE_TTL_MS &&
    cached.jwks.keys.some(key => key.kid === kid)
  ) {
    return {
      jwks: cached.jwks,
      cache: 'hit'
    };
  }

  const response = await httpClient.get(jku, {
    timeout: 10000,
    maxRedirects: 0,
    maxContentLength: WEBHOOK_JWKS_MAX_BYTES,
    maxBodyLength: WEBHOOK_JWKS_MAX_BYTES,
    validateStatus: () => true,
    headers: { Accept: 'application/json' }
  });

  const contentType = String(response.headers?.['content-type'] || response.headers?.['Content-Type'] || '');
  if (contentType && !/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new Error('webhook_jwks_content_type_invalid');
  }

  if (response.status !== 200) {
    throw new Error('webhook_jwks_fetch_failed');
  }

  const jwks = validateWebhookJwks(response.data);
  if (!jwks.keys.some(key => key.kid === kid)) {
    throw new Error('webhook_jwk_not_found_after_refresh');
  }

  webhookJwksCache.set(jku, {
    fetched_at: now,
    jwks
  });

  return {
    jwks,
    cache: cached ? 'refresh' : 'miss'
  };
}

function webhookReceiptDirectory(environment = envMode()) {
  if (!['sandbox', 'live'].includes(String(environment))) throw new Error('invalid_webhook_receipt_environment');
  const configured = requiredConfig().webhookReceiptDir;
  return pathModule.resolve(configured, String(environment));
}

function webhookReceiptPath(eventId, environment = envMode()) {
  if (!/^[0-9a-f-]{36}$/i.test(String(eventId || ''))) throw new Error('invalid_webhook_event_id');
  return pathModule.join(webhookReceiptDirectory(environment), `${String(eventId).toLowerCase()}.json`);
}

function canonicalWebhookReceipt(receipt) {
  return JSON.stringify({
    version: receipt.version,
    provider: receipt.provider,
    environment: receipt.environment,
    event_id: receipt.event_id,
    event_type: receipt.event_type,
    event_version: receipt.event_version,
    payment_id: receipt.payment_id,
    webhook_timestamp: receipt.webhook_timestamp,
    signature_kid: receipt.signature_kid,
    signature_jku: receipt.signature_jku,
    raw_body_sha256: receipt.raw_body_sha256,
    observed_at: receipt.observed_at
  });
}

function validateStoredWebhookReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object') throw new Error('stored_webhook_receipt_invalid');
  if (receipt.version !== 1) throw new Error('stored_webhook_receipt_version_invalid');
  if (receipt.provider !== 'truelayer') throw new Error('stored_webhook_receipt_provider_invalid');
  if (!/^[0-9a-f-]{36}$/i.test(String(receipt.event_id || ''))) throw new Error('stored_webhook_receipt_event_id_invalid');
  if (typeof receipt.signature_kid !== 'string' || !receipt.signature_kid) throw new Error('stored_webhook_receipt_signature_kid_invalid');
  if (typeof receipt.signature_jku !== 'string' || receipt.signature_jku !== (receipt.environment === 'sandbox'
    ? 'https://webhooks.truelayer-sandbox.com/.well-known/jwks'
    : 'https://webhooks.truelayer.com/.well-known/jwks')) {
    throw new Error('stored_webhook_receipt_signature_jku_invalid');
  }
  if (!/^[0-9a-f]{64}$/i.test(String(receipt.raw_body_sha256 || ''))) throw new Error('stored_webhook_receipt_body_hash_invalid');
  if (!/^[0-9a-f]{64}$/i.test(String(receipt.receipt_sha256 || ''))) throw new Error('stored_webhook_receipt_hash_invalid');

  const calculated = crypto.createHash('sha256').update(canonicalWebhookReceipt(receipt)).digest('hex');
  const supplied = Buffer.from(receipt.receipt_sha256.toLowerCase(), 'hex');
  const expected = Buffer.from(calculated, 'hex');
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    throw new Error('stored_webhook_receipt_integrity_mismatch');
  }

  return calculated;
}

function observeWebhookEvent({
  eventId,
  eventType,
  eventVersion,
  paymentId,
  webhookTimestamp,
  rawBodySha256,
  environment,
  signatureKid,
  signatureJku
}) {
  if (!/^[0-9a-f-]{36}$/i.test(String(eventId || ''))) throw new Error('invalid_webhook_event_id');
  if (!/^[0-9a-f]{64}$/i.test(String(rawBodySha256 || ''))) throw new Error('invalid_webhook_body_hash');

  if (!['sandbox', 'live'].includes(String(environment))) throw new Error('invalid_webhook_receipt_environment');
  const directory = webhookReceiptDirectory(environment);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });

  const receiptPath = webhookReceiptPath(eventId, environment);
  const receipt = {
    version: 1,
    provider: 'truelayer',
    environment: String(environment),
    event_id: String(eventId).toLowerCase(),
    event_type: String(eventType || ''),
    event_version: eventVersion,
    payment_id: paymentId || null,
    webhook_timestamp: webhookTimestamp,
    signature_kid: String(signatureKid || ''),
    signature_jku: String(signatureJku || ''),
    raw_body_sha256: String(rawBodySha256).toLowerCase(),
    observed_at: new Date().toISOString()
  };
  receipt.receipt_sha256 = crypto.createHash('sha256').update(canonicalWebhookReceipt(receipt)).digest('hex');

  try {
    const fd = fs.openSync(receiptPath, 'wx', 0o600);
    try {
      fs.writeFileSync(fd, JSON.stringify(receipt, null, 2) + '\n', 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }

    // Best-effort directory fsync on platforms that support it.
    try {
      const dirFd = fs.openSync(directory, 'r');
      try {
        fs.fsyncSync(dirFd);
      } finally {
        fs.closeSync(dirFd);
      }
    } catch {
      // File fsync above is mandatory; directory fsync portability varies.
    }

    return {
      duplicate: false,
      receipt_path: receiptPath,
      receipt_sha256: receipt.receipt_sha256
    };
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
  }

  let stored;
  try {
    stored = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
  } catch {
    throw new Error('stored_webhook_receipt_unreadable');
  }

  validateStoredWebhookReceipt(stored);

  if (String(stored.event_id).toLowerCase() !== String(eventId).toLowerCase()) {
    throw new Error('stored_webhook_receipt_event_id_conflict');
  }

  if (String(stored.raw_body_sha256).toLowerCase() !== String(rawBodySha256).toLowerCase()) {
    throw new Error('webhook_event_id_body_conflict');
  }

  return {
    duplicate: true,
    receipt_path: receiptPath,
    receipt_sha256: stored.receipt_sha256
  };
}

async function verifyAndClassifyWebhook({ signature, path, headers, rawBody, httpClient = axios }) {
  const parsedSignature = parseDetachedTlSignature(signature);
  const jwksResult = await fetchWebhookJwks(
    httpClient,
    parsedSignature.header.jku,
    parsedSignature.header.kid
  );
  const verification = verifyWebhookSignature({
    signature,
    method: 'POST',
    path,
    headers,
    rawBody,
    jwks: jwksResult.jwks
  });

  let event;
  try {
    event = JSON.parse(rawBody.toString('utf8'));
  } catch {
    throw new Error('invalid_webhook_json');
  }

  if (!event || typeof event !== 'object') throw new Error('invalid_webhook_event');
  if (typeof event.type !== 'string' || !event.type) throw new Error('missing_webhook_type');
  if (!('event_version' in event)) throw new Error('missing_webhook_event_version');

  const paymentId = typeof event.payment_id === 'string' ? event.payment_id : null;
  const rawBodySha256 = crypto.createHash('sha256').update(rawBody).digest('hex');
  const localPaymentBinding = paymentId
    ? lookupPaymentBinding(paymentId, verification.environment)
    : { known: false };
  const replay = observeWebhookEvent({
    eventId: event.event_id,
    eventType: event.type,
    eventVersion: event.event_version,
    paymentId,
    webhookTimestamp: verification.timestamp.timestamp,
    rawBodySha256,
    environment: verification.environment,
    signatureKid: verification.kid,
    signatureJku: verification.jku
  });

  return {
    provider: 'truelayer',
    environment: verification.environment,
    webhook_verified: true,
    duplicate: replay.duplicate,
    event_id: event.event_id,
    event_type: event.type,
    event_version: event.event_version,
    payment_id: paymentId,
    known_local_payment_intent: localPaymentBinding.known,
    local_payment_binding_sha256: localPaymentBinding.binding_sha256 || null,
    signature_kid: verification.kid,
    jwks_cache: jwksResult.cache,
    webhook_timestamp: verification.timestamp.timestamp,
    raw_body_sha256: rawBodySha256,
    durable_event_receipt: true,
    event_receipt_sha256: replay.receipt_sha256,
    observation_only: true,
    payment_write_performed: false,
    bank_authorization_performed: false,
    value_moved_by_handler: false,
    creditor_settlement_proven: false,
    verified_value_flow: false,
    execution_graph: {
      edge: 'VERIFIED_READ_CANDIDATE',
      active: false,
      state: replay.duplicate ? 'VERIFIED_WEBHOOK_DUPLICATE' : 'VERIFIED_WEBHOOK_OBSERVATION',
      reason: 'Signature-verified provider event is observational evidence only and cannot by itself prove creditor settlement or activate value flow.'
    }
  };
}

function providerConfigStatus() {
  const cfg = requiredConfig();
  const missing = [];
  if (!cfg.clientId) missing.push('TRUELAYER_CLIENT_ID');
  if (!cfg.clientSecret) missing.push('TRUELAYER_CLIENT_SECRET');
  if (!cfg.signingKid) missing.push('TRUELAYER_SIGNING_KID');
  if (!cfg.privateKey) missing.push('TRUELAYER_PRIVATE_KEY_B64 or TRUELAYER_PRIVATE_KEY_PEM');

  return {
    provider: 'truelayer',
    environment: envMode(),
    configured: missing.length === 0,
    provider_probe_enabled: cfg.providerProbeEnabled,
    provider_probe_authorization_configured: Boolean(cfg.providerProbeSecret),
    missing
  };
}

function assertProviderConfigured() {
  const status = providerConfigStatus();
  if (!status.configured) {
    const err = new Error('TrueLayer provider authentication is fail-closed: required credentials/signing configuration is missing.');
    err.statusCode = 503;
    err.publicDetails = status;
    throw err;
  }
  return requiredConfig();
}

function assertOperatorAuthorization(authorizationHeader) {
  const cfg = requiredConfig();
  if (cfg.operatorSecret.length < 32) {
    const err = new Error('G-Bank operator authorization is not configured securely.');
    err.statusCode = 503;
    throw err;
  }

  const supplied = Buffer.from(String(authorizationHeader || ''), 'utf8');
  const expected = Buffer.from(cfg.operatorSecret, 'utf8');
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    const err = new Error('G-Bank operator authorization failed.');
    err.statusCode = 403;
    throw err;
  }

  return true;
}

function operatorAuthorizationMiddleware(req, res, next) {
  // TrueLayer must be able to reach the webhook without a G-Bank operator secret.
  // Its authentication boundary is the verified Tl-Signature/JWKS path instead.
  if (req.path === '/webhook' || req.path === '/return') return next();

  try {
    assertOperatorAuthorization(req.get('X-G-Bank-Operator-Authorization') || '');
    return next();
  } catch (err) {
    return res.status(err.statusCode || 403).json({
      error: err.message || 'G-Bank operator authorization failed.',
      payment_created: false,
      value_moved: false,
      verified_value_flow: false
    });
  }
}

router.use(operatorAuthorizationMiddleware);

function assertProviderProbeEnabled(authorizationHeader) {
  const cfg = requiredConfig();
  if (!cfg.providerProbeEnabled) {
    const err = new Error('Provider readiness probe is disabled. Set G_BANK_ENABLE_PROVIDER_PROBE=true to allow a non-payment TrueLayer authentication/signature check.');
    err.statusCode = 403;
    err.publicDetails = {
      provider: 'truelayer',
      environment: environmentSnapshot,
      provider_probe_enabled: false,
      payment_created: false,
      value_moved: false
    };
    throw err;
  }

  if (cfg.providerProbeSecret.length < 32) {
    const err = new Error('Provider readiness probe authorization is not configured securely.');
    err.statusCode = 503;
    throw err;
  }

  const supplied = Buffer.from(String(authorizationHeader || ''), 'utf8');
  const expected = Buffer.from(cfg.providerProbeSecret, 'utf8');
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    const err = new Error('Provider readiness probe authorization failed.');
    err.statusCode = 403;
    throw err;
  }
}

function configStatus() {
  const cfg = requiredConfig();
  const { live } = endpoints();
  const missing = [];
  if (!cfg.clientId) missing.push('TRUELAYER_CLIENT_ID');
  if (!cfg.clientSecret) missing.push('TRUELAYER_CLIENT_SECRET');
  if (!cfg.signingKid) missing.push('TRUELAYER_SIGNING_KID');
  if (!cfg.privateKey) missing.push('TRUELAYER_PRIVATE_KEY_B64 or TRUELAYER_PRIVATE_KEY_PEM');
  if (!cfg.returnUri) missing.push('TRUELAYER_RETURN_URI');
  if (cfg.operatorSecret.length < 32) missing.push('G_BANK_OPERATOR_SECRET(min 32 chars)');
  if (!cfg.webhookPath.startsWith('/') || cfg.webhookPath.includes('?')) missing.push('TRUELAYER_WEBHOOK_PATH(valid path without query)');
  if (!Number.isFinite(cfg.maxEur) || cfg.maxEur <= 0) missing.push('G_BANK_MAX_PAYMENT_EUR');
  if (live && !cfg.liveEnabled) missing.push('G_BANK_ENABLE_LIVE=true');
  const evidence = evidenceStatus();
  if (live && !cfg.approvalSecret) missing.push('G_BANK_APPROVAL_SECRET');
  if (live && !cfg.webhookReceiptDirExplicit) missing.push('G_BANK_WEBHOOK_RECEIPT_DIR(explicit persistent location)');
  if (live && !cfg.paymentIntentDirExplicit) missing.push('G_BANK_PAYMENT_INTENT_DIR(explicit persistent location)');
  if (live && !evidence.secret_rotation.valid) missing.push('G_BANK_SECRET_ROTATION_RECEIPT_FILE(valid)');
  if (live && !evidence.sandbox_verification.valid) missing.push('G_BANK_SANDBOX_VERIFICATION_RECEIPT_FILE(valid,fresh)');
  if (live && cfg.allowedBeneficiaryIbans.length === 0) missing.push('G_BANK_ALLOWED_BENEFICIARY_IBANS');

  return {
    provider: 'truelayer',
    environment: live ? 'live' : 'sandbox',
    provider_authentication: providerConfigStatus(),
    configured: missing.length === 0,
    missing,
    live_execution_enabled: live && cfg.liveEnabled,
    operator_authorization_configured: cfg.operatorSecret.length >= 32,
    live_approval_required: live,
    live_approval_configured: live ? Boolean(cfg.approvalSecret) : false,
    historical_secret_rotation_receipt_present: evidence.secret_rotation.valid,
    sandbox_verification_receipt_present: evidence.sandbox_verification.valid,
    evidence,
    allowed_beneficiary_count: cfg.allowedBeneficiaryIbans.length,
    max_payment_eur: Number.isFinite(cfg.maxEur) ? cfg.maxEur : 0
  };
}

function assertConfigured() {
  const status = configStatus();
  if (!status.configured) {
    const err = new Error('Open Banking is fail-closed: required configuration is missing.');
    err.statusCode = 503;
    err.publicDetails = status;
    throw err;
  }
  return requiredConfig();
}

function isValidIban(iban) {
  const compact = String(iban || '').replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(compact)) return false;

  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;

  for (const ch of rearranged) {
    const fragment = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of fragment) {
      remainder = (remainder * 10 + Number(digit)) % 97;
    }
  }

  return remainder === 1;
}

function approvalMessage({ idempotencyKey, amountInMinor, iban, reference }) {
  return [idempotencyKey, String(amountInMinor), iban, String(reference)].join('|');
}

function assertLiveApproval({ idempotencyKey, amountInMinor, iban, reference, approvalHeader }) {
  if (envMode() !== 'live') return;

  const cfg = assertConfigured();
  if (!cfg.allowedBeneficiaryIbans.includes(iban)) {
    throw Object.assign(new Error('Beneficiary is not present in the live G-Bank allowlist.'), { statusCode: 403 });
  }

  if (!idempotencyKey) {
    throw Object.assign(new Error('A caller-supplied Idempotency-Key is required for live payments.'), { statusCode: 400 });
  }

  const supplied = String(approvalHeader || '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) {
    throw Object.assign(new Error('Valid X-G-Bank-Approval is required for live payments.'), { statusCode: 403 });
  }

  const expected = crypto
    .createHmac('sha256', cfg.approvalSecret)
    .update(approvalMessage({ idempotencyKey, amountInMinor, iban, reference }))
    .digest('hex');

  const suppliedBuffer = Buffer.from(supplied, 'hex');
  const expectedBuffer = Buffer.from(expected, 'hex');
  if (suppliedBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)) {
    throw Object.assign(new Error('Live G-Bank approval did not match this payment intent.'), { statusCode: 403 });
  }
}

function hashText(value) {
  return crypto.createHash('sha256').update(String(value ?? ''), 'utf8').digest('hex');
}

function paymentIntentDirectory(environment = envMode()) {
  if (!['sandbox', 'live'].includes(String(environment))) throw new Error('invalid_payment_intent_environment');
  return pathModule.resolve(requiredConfig().paymentIntentDir, String(environment));
}

function paymentIntentReceiptPath(idempotencyKey, environment = envMode()) {
  if (!/^[0-9a-f-]{36}$/i.test(String(idempotencyKey || ''))) throw new Error('invalid_payment_intent_idempotency_key');
  return pathModule.join(paymentIntentDirectory(environment), `${String(idempotencyKey).toLowerCase()}.intent.json`);
}

function paymentCreatedReceiptPath(idempotencyKey, environment = envMode()) {
  if (!/^[0-9a-f-]{36}$/i.test(String(idempotencyKey || ''))) throw new Error('invalid_payment_intent_idempotency_key');
  return pathModule.join(paymentIntentDirectory(environment), `${String(idempotencyKey).toLowerCase()}.created.json`);
}

function paymentBindingPath(paymentId, environment = envMode()) {
  if (!/^[0-9a-f-]{36}$/i.test(String(paymentId || ''))) throw new Error('invalid_payment_binding_id');
  return pathModule.join(paymentIntentDirectory(environment), `payment-${String(paymentId).toLowerCase()}.json`);
}

function canonicalPaymentIntentReceipt(receipt) {
  return JSON.stringify({
    version: receipt.version,
    provider: receipt.provider,
    environment: receipt.environment,
    idempotency_key: receipt.idempotency_key,
    amount_in_minor: receipt.amount_in_minor,
    request_body_sha256: receipt.request_body_sha256,
    beneficiary_iban_sha256: receipt.beneficiary_iban_sha256,
    reference_sha256: receipt.reference_sha256,
    created_at: receipt.created_at
  });
}

function canonicalPaymentCreatedReceipt(receipt) {
  return JSON.stringify({
    version: receipt.version,
    provider: receipt.provider,
    environment: receipt.environment,
    idempotency_key: receipt.idempotency_key,
    payment_id: receipt.payment_id,
    provider_status: receipt.provider_status,
    request_body_sha256: receipt.request_body_sha256,
    hosted_page_uri_sha256: receipt.hosted_page_uri_sha256,
    created_at: receipt.created_at
  });
}

function canonicalPaymentBinding(receipt) {
  return JSON.stringify({
    version: receipt.version,
    provider: receipt.provider,
    environment: receipt.environment,
    payment_id: receipt.payment_id,
    idempotency_key_sha256: receipt.idempotency_key_sha256,
    request_body_sha256: receipt.request_body_sha256,
    created_receipt_sha256: receipt.created_receipt_sha256,
    created_at: receipt.created_at
  });
}

function integrityHash(canonical) {
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

function atomicCreateJson(filePath, record) {
  const directory = pathModule.dirname(filePath);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const fd = fs.openSync(filePath, 'wx', 0o600);
  try {
    fs.writeFileSync(fd, JSON.stringify(record, null, 2) + '\n', 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    const dirFd = fs.openSync(directory, 'r');
    try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
  } catch {
    // Directory fsync portability varies; file fsync above is mandatory.
  }
}

function readAndValidatePaymentIntentReceipt(filePath) {
  const receipt = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (receipt.version !== 1 || receipt.provider !== 'truelayer') throw new Error('payment_intent_receipt_invalid');
  const calculated = integrityHash(canonicalPaymentIntentReceipt(receipt));
  if (calculated !== receipt.receipt_sha256) throw new Error('payment_intent_receipt_integrity_mismatch');
  return receipt;
}

function readAndValidatePaymentCreatedReceipt(filePath) {
  const receipt = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (receipt.version !== 1 || receipt.provider !== 'truelayer') throw new Error('payment_created_receipt_invalid');
  const calculated = integrityHash(canonicalPaymentCreatedReceipt(receipt));
  if (calculated !== receipt.receipt_sha256) throw new Error('payment_created_receipt_integrity_mismatch');
  return receipt;
}

function readAndValidatePaymentBinding(filePath) {
  const receipt = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (receipt.version !== 1 || receipt.provider !== 'truelayer') throw new Error('payment_binding_invalid');
  const calculated = integrityHash(canonicalPaymentBinding(receipt));
  if (calculated !== receipt.binding_sha256) throw new Error('payment_binding_integrity_mismatch');
  return receipt;
}

function preparePaymentIntentReceipt({ idempotencyKey, amountInMinor, beneficiary, rawBody, environment }) {
  const receiptPath = paymentIntentReceiptPath(idempotencyKey, environment);
  const requestBodySha256 = hashText(rawBody);
  const expected = {
    version: 1,
    provider: 'truelayer',
    environment,
    idempotency_key: String(idempotencyKey).toLowerCase(),
    amount_in_minor: amountInMinor,
    request_body_sha256: requestBodySha256,
    beneficiary_iban_sha256: hashText(String(beneficiary.iban).toUpperCase()),
    reference_sha256: hashText(String(beneficiary.reference)),
    created_at: new Date().toISOString()
  };
  expected.receipt_sha256 = integrityHash(canonicalPaymentIntentReceipt(expected));

  try {
    atomicCreateJson(receiptPath, expected);
    return { created: true, receipt: expected, receipt_path: receiptPath };
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
  }

  const stored = readAndValidatePaymentIntentReceipt(receiptPath);
  if (
    stored.request_body_sha256 !== requestBodySha256 ||
    stored.amount_in_minor !== amountInMinor ||
    stored.beneficiary_iban_sha256 !== expected.beneficiary_iban_sha256 ||
    stored.reference_sha256 !== expected.reference_sha256
  ) {
    throw Object.assign(new Error('Idempotency-Key was already bound to a different payment intent.'), { statusCode: 409 });
  }

  const createdPath = paymentCreatedReceiptPath(idempotencyKey, environment);
  if (fs.existsSync(createdPath)) {
    const created = readAndValidatePaymentCreatedReceipt(createdPath);
    throw Object.assign(new Error('Payment intent was already created at the provider; use its payment ID for status instead of creating again.'), {
      statusCode: 409,
      publicDetails: {
        payment_id: created.payment_id,
        provider_status: created.provider_status,
        retry_create_denied: true
      }
    });
  }

  throw Object.assign(new Error('A prior submission with this Idempotency-Key has no confirmed provider result. Automatic retry is denied; review provider state before any retry.'), {
    statusCode: 409,
    publicDetails: {
      ambiguous_prior_submission: true,
      retry_create_denied: true
    }
  });
}

function recordPaymentCreated({ idempotencyKey, payment, rawBody, environment }) {
  if (!/^[0-9a-f-]{36}$/i.test(String(payment?.id || ''))) {
    throw new Error('TrueLayer payment creation response did not contain a valid payment ID.');
  }

  const createdPath = paymentCreatedReceiptPath(idempotencyKey, environment);
  const receipt = {
    version: 1,
    provider: 'truelayer',
    environment,
    idempotency_key: String(idempotencyKey).toLowerCase(),
    payment_id: String(payment.id).toLowerCase(),
    provider_status: String(payment.status || ''),
    request_body_sha256: hashText(rawBody),
    hosted_page_uri_sha256: payment.hosted_page?.uri ? hashText(payment.hosted_page.uri) : null,
    created_at: new Date().toISOString()
  };
  receipt.receipt_sha256 = integrityHash(canonicalPaymentCreatedReceipt(receipt));
  atomicCreateJson(createdPath, receipt);

  const bindingPath = paymentBindingPath(payment.id, environment);
  const binding = {
    version: 1,
    provider: 'truelayer',
    environment,
    payment_id: String(payment.id).toLowerCase(),
    idempotency_key_sha256: hashText(String(idempotencyKey).toLowerCase()),
    request_body_sha256: receipt.request_body_sha256,
    created_receipt_sha256: receipt.receipt_sha256,
    created_at: receipt.created_at
  };
  binding.binding_sha256 = integrityHash(canonicalPaymentBinding(binding));
  atomicCreateJson(bindingPath, binding);

  return {
    created_receipt_sha256: receipt.receipt_sha256,
    payment_binding_sha256: binding.binding_sha256
  };
}

function lookupPaymentBinding(paymentId, environment = envMode()) {
  const filePath = paymentBindingPath(paymentId, environment);
  if (!fs.existsSync(filePath)) return { known: false };
  const binding = readAndValidatePaymentBinding(filePath);
  return {
    known: true,
    environment: binding.environment,
    payment_id: binding.payment_id,
    binding_sha256: binding.binding_sha256,
    created_receipt_sha256: binding.created_receipt_sha256
  };
}

function assertPaymentInput(body) {
  const amountText = String(body?.amount_eur ?? '').trim();
  if (!/^\d+(?:\.\d{1,2})?$/.test(amountText)) {
    throw Object.assign(new Error('amount_eur must be a positive EUR amount with at most 2 decimals.'), { statusCode: 400 });
  }

  const normalizedAmountInMinor = Math.round(Number(amountText) * 100);
  if (!Number.isSafeInteger(normalizedAmountInMinor) || normalizedAmountInMinor <= 0) {
    throw Object.assign(new Error('amount_eur is outside the supported range.'), { statusCode: 400 });
  }
  const amountEur = normalizedAmountInMinor / 100;

  const cfg = requiredConfig();
  if (amountEur > cfg.maxEur) {
    throw Object.assign(new Error('Payment exceeds G_BANK_MAX_PAYMENT_EUR.'), { statusCode: 400 });
  }

  const beneficiary = body?.beneficiary || {};
  const user = body?.user || {};
  const address = user.address || {};

  const iban = String(beneficiary.iban || '').replace(/\s+/g, '').toUpperCase();
  if (!isValidIban(iban)) {
    throw Object.assign(new Error('beneficiary.iban is required and must pass IBAN checksum validation.'), { statusCode: 400 });
  }
  if (!beneficiary.name || !beneficiary.reference) {
    throw Object.assign(new Error('beneficiary.name and beneficiary.reference are required.'), { statusCode: 400 });
  }

  const requiredUser = ['name', 'email', 'phone', 'date_of_birth'];
  for (const key of requiredUser) {
    if (!user[key]) throw Object.assign(new Error(`user.${key} is required.`), { statusCode: 400 });
  }

  for (const key of ['address_line1', 'city', 'zip', 'country_code']) {
    if (!address[key]) throw Object.assign(new Error(`user.address.${key} is required.`), { statusCode: 400 });
  }

  return { amountEur, amountInMinor: normalizedAmountInMinor, beneficiary: { ...beneficiary, iban }, user: { ...user, address } };
}

async function getAccessToken(httpClient = axios) {
  const cfg = assertProviderConfigured();
  const { authBase } = endpoints();
  const params = new URLSearchParams();
  params.set('grant_type', 'client_credentials');
  params.set('client_id', cfg.clientId);
  params.set('client_secret', cfg.clientSecret);
  params.set('scope', 'payments');

  const response = await httpClient.post(`${authBase}/connect/token`, params.toString(), {
    timeout: 15000,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });

  if (!response.data?.access_token) throw new Error('TrueLayer token response did not contain access_token.');
  return response.data.access_token;
}

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function buildTrueLayerSigningPayload({ method, path, headers = {}, body = '' }) {
  const normalizedMethod = String(method || '').toUpperCase();
  if (!path || !String(path).startsWith('/')) {
    throw new Error('TrueLayer signing path must start with /.');
  }
  if (typeof body !== 'string') {
    throw new Error('TrueLayer signing body must be a string.');
  }

  let payload = `${normalizedMethod} ${path}\n`;
  for (const [name, value] of Object.entries(headers)) {
    payload += `${name}: ${value}\n`;
  }
  payload += body;
  return payload;
}

function signRequest({ method, path, body = '', idempotencyKey }) {
  const cfg = assertProviderConfigured();
  if (!idempotencyKey) {
    throw new Error('Idempotency-Key is required for TrueLayer request signing.');
  }

  const headers = { 'Idempotency-Key': idempotencyKey };
  const joseHeader = {
    alg: 'ES512',
    kid: cfg.signingKid,
    tl_version: '2',
    tl_headers: Object.keys(headers).join(',')
  };

  const encodedHeader = base64url(JSON.stringify(joseHeader));
  const signingPayload = buildTrueLayerSigningPayload({ method, path, headers, body });
  const encodedPayload = base64url(signingPayload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto.sign('sha512', Buffer.from(signingInput, 'utf8'), {
    key: cfg.privateKey,
    dsaEncoding: 'ieee-p1363'
  });

  if (signature.length !== 132) {
    throw new Error('TrueLayer ES512 signing requires a P-521 private key.');
  }

  return `${encodedHeader}..${signature.toString('base64url')}`;
}

async function performProviderReadiness(httpClient = axios, authorizationHeader = '') {
  assertProviderProbeEnabled(authorizationHeader);
  assertProviderConfigured();

  // Snapshot the environment endpoints once so a single operation cannot
  // observe mixed sandbox/live configuration across asynchronous boundaries.
  const endpointSnapshot = endpoints();
  const path = '/test-signature';
  const nonce = crypto.randomUUID();
  const rawBody = JSON.stringify({ nonce });
  const idempotencyKey = crypto.randomUUID();
  const token = await getAccessToken(httpClient);
  const signature = signRequest({
    method: 'POST',
    path,
    body: rawBody,
    idempotencyKey
  });
  const apiBase = endpointSnapshot.apiBase;

  const response = await httpClient.post(`${apiBase}${path}`, rawBody, {
    timeout: 15000,
    validateStatus: () => true,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Idempotency-Key': idempotencyKey,
      'Tl-Signature': signature
    }
  });

  const signatureValid = response.status === 204;

  return {
    provider: 'truelayer',
    environment: endpointSnapshot.live ? 'live' : 'sandbox',
    access_token_obtained: true,
    request_signature_accepted: signatureValid,
    provider_http_status: response.status,
    payment_created: false,
    bank_authorization_started: false,
    value_moved: false,
    verified_write: false,
    verified_value_flow: false,
    execution_graph: {
      candidate_state: signatureValid ? 'AUTHENTICATED_TESTED' : 'AUTHENTICATION_OR_SIGNATURE_FAILED',
      verified_read: false,
      verified_write: false,
      verified_value_flow: false,
      reason: signatureValid
        ? 'TrueLayer accepted the non-payment signed readiness request. This proves provider authentication/signing only.'
        : 'TrueLayer did not return 204 for the non-payment signature test.'
    }
  };
}

function executionGraphStatus() {
  const cfg = requiredConfig();
  const provider = providerConfigStatus();
  const live = envMode() === 'live';

  const providerState = !provider.configured
    ? 'CREDENTIAL_REQUIRED'
    : cfg.providerProbeEnabled
      ? 'PROBE_ENABLED_NOT_YET_VERIFIED'
      : 'CONFIGURED_NOT_EXTERNALLY_VERIFIED';

  const evidence = evidenceStatus();
  const liveReleaseEvidencePresent =
    evidence.secret_rotation.valid &&
    evidence.sandbox_verification.valid;

  return {
    graph: 'G_REAL_EXECUTION_GRAPH',
    provider: 'truelayer',
    environment: envMode(),
    edges: {
      provider_authentication: {
        class: 'VERIFIED_READ_CANDIDATE',
        state: providerState,
        active: false,
        reason: 'Local configuration is not external provider proof. Promote only after a successful non-payment provider readiness receipt.'
      },
      provider_webhook: {
        class: 'VERIFIED_READ_CANDIDATE',
        state: 'AWAITING_SIGNATURE_VERIFIED_EVENT',
        active: false,
        reason: 'Webhook observations require exact TrueLayer JKU/JWKS verification and remain observational evidence only.'
      },
      payment_creation: {
        class: 'VERIFIED_WRITE_CANDIDATE',
        state: 'BLOCKED_UNTIL_EXPLICIT_PAYMENT_INTENT',
        active: false,
        reason: 'Payment creation requires an explicit request and does not follow from provider readiness.'
      },
      value_flow: {
        class: 'VERIFIED_VALUE_FLOW',
        state: 'BLOCKED',
        active: false,
        reason: 'Requires explicit bank authorization, bank execution evidence and independent settlement/receipt evidence.'
      }
    },
    release_gates: {
      live_environment_selected: live,
      live_enable_flag: cfg.liveEnabled,
      operator_authorization_configured: cfg.operatorSecret.length >= 32,
      historical_secret_rotation_receipt_present: evidence.secret_rotation.valid,
      sandbox_verification_receipt_present: evidence.sandbox_verification.valid,
      live_release_evidence_present: liveReleaseEvidencePresent,
      beneficiary_allowlist_configured: cfg.allowedBeneficiaryIbans.length > 0,
      transaction_approval_secret_configured: Boolean(cfg.approvalSecret),
      webhook_receipt_store_configured: Boolean(cfg.webhookReceiptDir),
      webhook_receipt_store_explicit: cfg.webhookReceiptDirExplicit,
      payment_intent_store_configured: Boolean(cfg.paymentIntentDir),
      payment_intent_store_explicit: cfg.paymentIntentDirExplicit
    },
    verified_value_flow: false
  };
}

router.get('/health', (req, res) => {
  res.json({
    ...configStatus(),
    bank_authorization_required: true,
    verified_value_flow: false
  });
});

router.get('/graph-status', (req, res) => {
  res.json(executionGraphStatus());
});


router.get('/return', (req, res) => {
  const paymentId = String(req.query.payment_id || '');
  const error = String(req.query.error || '');

  if (!/^[0-9a-f-]{36}$/i.test(paymentId)) {
    return res.status(400).json({
      error: 'Invalid or missing payment_id.',
      payment_success: null,
      verified_value_flow: false
    });
  }

  const binding = lookupPaymentBinding(paymentId, envMode());
  if (!binding.known) {
    return res.status(404).json({
      provider: 'truelayer',
      payment_id: paymentId,
      known_local_payment_intent: false,
      payment_success: null,
      verified_value_flow: false,
      next_action: 'Do not infer payment outcome from this return URL.'
    });
  }

  return res.status(200).json({
    provider: 'truelayer',
    environment: binding.environment,
    payment_id: paymentId,
    known_local_payment_intent: true,
    authorization_flow_returned: true,
    authorization_abandoned: error === 'tl_hpp_abandoned',
    return_error: error === 'tl_hpp_abandoned' ? 'tl_hpp_abandoned' : null,
    payment_success: null,
    bank_accepted_execution: false,
    creditor_settlement_proven: false,
    verified_value_flow: false,
    next_action: 'Wait for a signature-verified webhook or use the authenticated payment-status endpoint.'
  });
});

router.post('/provider-readiness', async (req, res) => {
  try {
    const result = await performProviderReadiness(
      axios,
      req.get('X-G-Bank-Probe-Authorization') || ''
    );
    res.status(result.request_signature_accepted ? 200 : 502).json(result);
  } catch (err) {
    const status = err.statusCode || err.response?.status || 500;
    res.status(status).json({
      error: err.message || 'TrueLayer provider readiness check failed.',
      details: err.publicDetails || err.response?.data || undefined,
      payment_created: false,
      value_moved: false,
      verified_value_flow: false
    });
  }
});

router.post('/webhook', async (req, res) => {
  try {
    const path = `${req.baseUrl}${req.path}`;
    const result = await verifyAndClassifyWebhook({
      signature: req.get('Tl-Signature') || '',
      path,
      headers: req.headers,
      rawBody: req.rawBody,
      httpClient: axios
    });

    // Duplicates are acknowledged with 2xx to stop provider retries.
    res.status(200).json(result);
  } catch (err) {
    res.status(401).json({
      error: err.message || 'Webhook verification failed.',
      webhook_verified: false,
      observation_only: true,
      value_moved_by_handler: false,
      verified_value_flow: false
    });
  }
});

router.post('/create-payment', async (req, res) => {
  try {
    assertConfigured();
    const { amountEur, amountInMinor, beneficiary, user } = assertPaymentInput(req.body);
    const path = '/v3/payments';
    const callerIdempotencyKey = req.get('Idempotency-Key');
    const idempotencyKey = callerIdempotencyKey || crypto.randomUUID();

    assertLiveApproval({
      idempotencyKey: callerIdempotencyKey,
      amountInMinor,
      iban: beneficiary.iban,
      reference: beneficiary.reference,
      approvalHeader: req.get('X-G-Bank-Approval')
    });

    const payload = {
      amount_in_minor: amountInMinor,
      currency: 'EUR',
      payment_method: {
        type: 'bank_transfer',
        provider_selection: {
          type: 'user_selected',
          filter: {
            countries: ['NL'],
            customer_segments: ['retail']
          },
          scheme_selection: {
            type: 'user_selected',
            allow_remitter_fee: false
          }
        },
        beneficiary: {
          type: 'external_account',
          account_holder_name: String(beneficiary.name),
          account_identifier: {
            type: 'iban',
            iban: beneficiary.iban
          },
          reference: String(beneficiary.reference).slice(0, 18)
        }
      },
      hosted_page: {
        return_uri: requiredConfig().returnUri,
        country_code: 'NL',
        language_code: 'nl'
      },
      user: {
        name: String(user.name),
        email: String(user.email),
        phone: String(user.phone),
        date_of_birth: String(user.date_of_birth),
        address: {
          address_line1: String(user.address.address_line1),
          ...(user.address.address_line2 ? { address_line2: String(user.address.address_line2) } : {}),
          city: String(user.address.city),
          ...(user.address.state ? { state: String(user.address.state) } : {}),
          zip: String(user.address.zip),
          country_code: String(user.address.country_code).toUpperCase()
        }
      },
      metadata: {
        g_bank: 'true',
        execution_graph_edge: 'VERIFIED_VALUE_FLOW_CANDIDATE'
      }
    };

    const rawBody = JSON.stringify(payload);
    const environmentSnapshot = envMode();
    const intentReceipt = preparePaymentIntentReceipt({
      idempotencyKey,
      amountInMinor,
      beneficiary,
      rawBody,
      environment: environmentSnapshot
    });
    const token = await getAccessToken();
    const signature = signRequest({ method: 'POST', path, body: rawBody, idempotencyKey });
    const { apiBase } = endpoints();

    const response = await axios.post(`${apiBase}${path}`, rawBody, {
      timeout: 20000,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': idempotencyKey,
        'Tl-Signature': signature
      }
    });

    const payment = response.data || {};
    const creationReceipts = recordPaymentCreated({
      idempotencyKey,
      payment,
      rawBody,
      environment: environmentSnapshot
    });
    res.status(201).json({
      provider: 'truelayer',
      environment: envMode(),
      payment_id: payment.id,
      status: payment.status,
      authorization_required: true,
      authorization_url: payment.hosted_page?.uri || null,
      idempotency_key: idempotencyKey,
      intent_receipt_sha256: intentReceipt.receipt.receipt_sha256,
      created_receipt_sha256: creationReceipts.created_receipt_sha256,
      payment_binding_sha256: creationReceipts.payment_binding_sha256,
      execution_graph: {
        edge: 'VERIFIED_VALUE_FLOW_CANDIDATE',
        active: false,
        reason: 'End-user bank authorization and external execution confirmation still required.'
      }
    });
  } catch (err) {
    const status = err.statusCode || err.response?.status || 500;
    res.status(status).json({
      error: err.message || 'Open Banking payment creation failed.',
      details: err.publicDetails || err.response?.data || undefined
    });
  }
});

async function fetchPaymentStatus(paymentId, httpClient = axios) {
  if (!/^[0-9a-f-]{36}$/i.test(String(paymentId || ''))) {
    const err = new Error('Invalid payment ID.');
    err.statusCode = 400;
    throw err;
  }

  assertProviderConfigured();
  const endpointSnapshot = endpoints();
  const path = `/v3/payments/${paymentId}`;
  const token = await getAccessToken(httpClient);

  const response = await httpClient.get(`${endpointSnapshot.apiBase}${path}`, {
    timeout: 15000,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json; charset=UTF-8'
    }
  });

  return {
    environment: endpointSnapshot.live ? 'live' : 'sandbox',
    payment: response.data || {}
  };
}

router.get('/payment/:paymentId', async (req, res) => {
  try {
    const paymentId = String(req.params.paymentId || '');
    const result = await fetchPaymentStatus(paymentId, axios);
    const payment = result.payment;
    const status = String(payment.status || '');
    const executed = status === 'executed' || status === 'payment_executed';
    const failed = status === 'failed' || status === 'payment_failed';

    res.json({
      provider: 'truelayer',
      environment: result.environment,
      payment_id: payment.id || paymentId,
      status,
      failed,
      bank_accepted_execution: executed,
      creditor_settlement_proven: false,
      verified_value_flow: false,
      value_flow_state: executed
        ? 'BANK_ACCEPTED_NOT_SETTLEMENT_PROVEN'
        : failed
          ? 'FAILED'
          : 'PENDING_AUTHORIZATION_OR_EXECUTION',
      execution_graph: {
        edge: 'VERIFIED_VALUE_FLOW_CANDIDATE',
        active: false,
        reason: executed
          ? 'The bank accepted the external-account payment, but creditor settlement is not proven by TrueLayer executed status alone.'
          : failed
            ? 'Payment failed; value-flow edge remains inactive.'
            : 'Awaiting end-user bank authorization and execution confirmation.'
      },
      executed_at: payment.executed_at || null
    });
  } catch (err) {
    const status = err.statusCode || err.response?.status || 500;
    res.status(status).json({
      error: err.message || 'Open Banking payment status check failed.',
      details: err.publicDetails || err.response?.data || undefined
    });
  }
});

router._test = {
  envMode,
  providerConfigStatus,
  configStatus,
  assertOperatorAuthorization,
  operatorAuthorizationMiddleware,
  assertProviderProbeEnabled,
  isValidIban,
  approvalMessage,
  hashText,
  paymentIntentDirectory,
  paymentIntentReceiptPath,
  paymentCreatedReceiptPath,
  paymentBindingPath,
  readAndValidatePaymentIntentReceipt,
  readAndValidatePaymentCreatedReceipt,
  readAndValidatePaymentBinding,
  preparePaymentIntentReceipt,
  recordPaymentCreated,
  lookupPaymentBinding,
  assertPaymentInput,
  assertLiveApproval,
  buildTrueLayerSigningPayload,
  signRequest,
  getAccessToken,
  performProviderReadiness,
  executionGraphStatus,
  validateEvidenceReceipt,
  evidenceStatus,
  expectedWebhookJku,
  parseDetachedTlSignature,
  validateWebhookTimestamp,
  buildWebhookSigningPayload,
  verifyWebhookSignature,
  validateWebhookJwks,
  clearWebhookJwksCache,
  fetchWebhookJwks,
  webhookReceiptDirectory,
  webhookReceiptPath,
  validateStoredWebhookReceipt,
  observeWebhookEvent,
  verifyAndClassifyWebhook,
  fetchPaymentStatus
};

module.exports = router;
