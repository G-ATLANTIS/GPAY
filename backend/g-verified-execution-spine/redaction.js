'use strict';

// Redaction + secret-leak detection for everything the spine writes to
// receipts, the audit ledger, and returned results. Secrets, tokens, private
// keys, OAuth credentials, bank credentials and raw sensitive payloads must
// never leave the process boundary in evidence.

const REDACTED = '[REDACTED]';

const SENSITIVE_KEY_PATTERNS = [
  /token/i,
  /secret/i,
  /password/i,
  /passphrase/i,
  /api[_-]?key/i,
  /authorization/i,
  /credential/i,
  /private[_-]?key/i,
  /client[_-]?secret/i,
  /access[_-]?token/i,
  /refresh[_-]?token/i,
  /session[_-]?id/i,
  /^cookie$/i,
  /^pan$/i,
  /^cvv$/i,
  /card[_-]?number/i,
  /^iban$/i,
  /account[_-]?number/i,
  /routing[_-]?number/i,
  /^bearer$/i,
  /mnemonic/i,
  /seed[_-]?phrase/i,
  // Personal data that must not sit in audit evidence in the clear.
  /^email$/i,
  /^phone$/i,
  /phone[_-]?number/i,
  /date[_-]?of[_-]?birth/i,
  /^dob$/i,
  /address[_-]?line/i,
  /postal[_-]?code/i,
  /^zip$/i,
  /holder[_-]?name/i,
  /account[_-]?holder/i,
  /beneficiary[_-]?name/i,
  /full[_-]?name/i,
];

// Value shapes that look like live credentials even under a benign key name.
const SECRET_VALUE_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bBearer\s+[A-Za-z0-9._-]{10,}/,
  /\blive_[A-Za-z0-9]{20,}/, // Mollie live key
  /\bsk_(live|test)_[A-Za-z0-9]{16,}/, // Stripe-style secret key
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/, // Slack token
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, // JWT
  /\bAKIA[0-9A-Z]{16}\b/, // AWS access key id
  /\bghp_[A-Za-z0-9]{20,}/, // GitHub PAT
];

function isSensitiveKey(key) {
  return SENSITIVE_KEY_PATTERNS.some((re) => re.test(String(key)));
}

function looksLikeSecretValue(value) {
  if (typeof value !== 'string') return false;
  return SECRET_VALUE_PATTERNS.some((re) => re.test(value));
}

// Returns a deep copy with sensitive keys and secret-looking values masked.
function redact(input, seen = new WeakSet()) {
  if (input === null || typeof input !== 'object') {
    return looksLikeSecretValue(input) ? REDACTED : input;
  }
  if (seen.has(input)) return '[CIRCULAR]';
  seen.add(input);

  if (Array.isArray(input)) return input.map((v) => redact(v, seen));

  const out = {};
  for (const [key, value] of Object.entries(input)) {
    if (isSensitiveKey(key)) {
      out[key] = REDACTED;
    } else {
      out[key] = redact(value, seen);
    }
  }
  return out;
}

// Walk a (already redacted) structure and throw if any secret material survived.
// This is the last line of defense before an evidence write.
function assertNoSecrets(input, pathParts = ['$'], seen = new WeakSet()) {
  const path = pathParts.join('.');
  if (input === null || input === undefined) return;
  if (typeof input === 'string') {
    if (looksLikeSecretValue(input)) {
      throw new Error(`secret_material_in_evidence:${path}`);
    }
    return;
  }
  if (typeof input !== 'object') return;
  if (seen.has(input)) return;
  seen.add(input);

  if (Array.isArray(input)) {
    input.forEach((v, i) => assertNoSecrets(v, [...pathParts, String(i)], seen));
    return;
  }
  for (const [key, value] of Object.entries(input)) {
    if (isSensitiveKey(key) && value !== REDACTED && value !== '[CIRCULAR]') {
      throw new Error(`unredacted_sensitive_key_in_evidence:${path}.${key}`);
    }
    assertNoSecrets(value, [...pathParts, key], seen);
  }
}

// Convenience: redact then hard-assert. Use for every ledger/receipt payload.
function safeEvidence(input) {
  const cleaned = redact(input);
  assertNoSecrets(cleaned);
  return cleaned;
}

module.exports = {
  REDACTED,
  redact,
  assertNoSecrets,
  safeEvidence,
  isSensitiveKey,
  looksLikeSecretValue,
};
