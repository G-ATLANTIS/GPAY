#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
function sha256(v) { return crypto.createHash('sha256').update(String(v ?? '')).digest('hex'); }

function institutionRegistration(input = {}) {
  const institutionId = String(input.institution_id || '').trim();
  const provider = String(input.provider || '').trim();
  const environment = String(input.environment || '').toUpperCase();
  const registrationState = String(input.registration_state || 'PENDING').toUpperCase();
  if (!institutionId || !provider) throw new Error('institution_identity_required');
  if (!['SANDBOX','PRODUCTION'].includes(environment)) throw new Error('institution_environment_invalid');
  const record = {
    schema: 'atlas-institution-registration-v1',
    institution_id: institutionId,
    provider,
    environment,
    registration_state: registrationState,
    pisp_identity: String(input.pisp_identity || '').trim() || null,
    callback_origin_sha256: input.callback_origin ? sha256(input.callback_origin) : null,
    credentials_present: input.credentials_present === true,
    certificate_binding_verified: input.certificate_binding_verified === true,
    last_probe_verified: input.last_probe_verified === true,
    last_probe_at: input.last_probe_at || null
  };
  record.registration_sha256 = sha256(JSON.stringify(record));
  return Object.freeze(record);
}

function evaluateRegistration(record, { now = new Date(), max_probe_age_seconds = 86400 } = {}) {
  const blockers = [];
  if (!record || record.schema !== 'atlas-institution-registration-v1') throw new Error('registration_schema_invalid');
  if (record.environment !== 'PRODUCTION') blockers.push('PRODUCTION_REGISTRATION_REQUIRED');
  if (record.registration_state !== 'REGISTERED') blockers.push('BANK_REGISTRATION_NOT_COMPLETE');
  if (record.credentials_present !== true) blockers.push('BANK_CREDENTIALS_MISSING');
  if (record.certificate_binding_verified !== true) blockers.push('CERTIFICATE_BINDING_NOT_VERIFIED');
  if (record.last_probe_verified !== true) blockers.push('BANK_PROBE_NOT_VERIFIED');
  const probe = Date.parse(record.last_probe_at);
  if (!Number.isFinite(probe) || now.getTime() - probe > max_probe_age_seconds * 1000) blockers.push('BANK_PROBE_STALE');
  return { schema: 'atlas-institution-registration-readiness-v1', state: blockers.length ? 'BLOCKED' : 'READY', blockers };
}

module.exports = { institutionRegistration, evaluateRegistration, sha256 };
