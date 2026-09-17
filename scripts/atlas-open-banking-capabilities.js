#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');

function sha256(value) {
  return crypto.createHash('sha256').update(String(value ?? '')).digest('hex');
}

function normalizeInstitution(record = {}) {
  const id = String(record.institution_id || '').trim();
  if (!id) throw new Error('institution_id_required');
  const countries = Array.from(new Set((record.countries || []).map(v => String(v).toUpperCase()))).sort();
  const schemes = Array.from(new Set((record.schemes || []).map(String))).sort();
  const observedAt = Date.parse(record.observed_at);
  const expiresAt = Date.parse(record.expires_at);
  if (!Number.isFinite(observedAt) || !Number.isFinite(expiresAt) || expiresAt <= observedAt) {
    throw new Error('capability_time_invalid');
  }
  const out = {
    institution_id: id,
    provider: String(record.provider || '').trim(),
    countries,
    schemes,
    payment_initiation: record.payment_initiation === true,
    sca_supported: record.sca_supported === true,
    max_amount_in_minor: Number.isSafeInteger(record.max_amount_in_minor) ? record.max_amount_in_minor : null,
    registration_state: String(record.registration_state || 'UNKNOWN'),
    observed_at: new Date(observedAt).toISOString(),
    expires_at: new Date(expiresAt).toISOString()
  };  out.capability_sha256 = sha256(JSON.stringify(out));
  return Object.freeze(out);
}

function evaluateInstitution({ capability, amount_in_minor, country = 'NL', scheme = 'sepa_credit_transfer', now = new Date() }) {
  const cap = normalizeInstitution(capability);
  const blockers = [];
  const ts = now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(ts)) throw new Error('now_invalid');
  if (Date.parse(cap.expires_at) <= ts) blockers.push('CAPABILITY_EVIDENCE_STALE');
  if (cap.payment_initiation !== true) blockers.push('PAYMENT_INITIATION_UNSUPPORTED');
  if (cap.sca_supported !== true) blockers.push('SCA_UNSUPPORTED');
  if (!cap.countries.includes(String(country).toUpperCase())) blockers.push('COUNTRY_UNSUPPORTED');
  if (!cap.schemes.includes(String(scheme))) blockers.push('SCHEME_UNSUPPORTED');
  if (cap.registration_state !== 'REGISTERED') blockers.push('INSTITUTION_NOT_REGISTERED');
  if (!Number.isSafeInteger(cap.max_amount_in_minor)) blockers.push('BANK_LIMIT_UNVERIFIED');
  else if (cap.max_amount_in_minor < Number(amount_in_minor)) blockers.push('BANK_LIMIT_INSUFFICIENT');
  return {
    schema: 'atlas-institution-capability-evaluation-v1',
    institution_id: cap.institution_id,
    capability_sha256: cap.capability_sha256,
    state: blockers.length ? 'BLOCKED' : 'ELIGIBLE',
    blockers: Array.from(new Set(blockers)).sort(),
    network_request_performed: false,
    value_moved: false
  };
}

module.exports = { normalizeInstitution, evaluateInstitution, sha256 };
