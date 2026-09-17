#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
function sha256(v) { return crypto.createHash('sha256').update(String(v ?? '')).digest('hex'); }

function certificateRecord(input = {}) {
  const type = String(input.type || '').toUpperCase();
  if (!['QWAC','QSEAL'].includes(type)) throw new Error('certificate_type_invalid');
  const serial = String(input.serial || '').trim();
  const issuer = String(input.issuer || '').trim();
  const notBefore = Date.parse(input.not_before);
  const notAfter = Date.parse(input.not_after);
  if (!serial || !issuer || !Number.isFinite(notBefore) || !Number.isFinite(notAfter) || notAfter <= notBefore) {
    throw new Error('certificate_metadata_invalid');
  }
  if (input.private_key_exportable === true) throw new Error('private_key_must_be_non_exportable');
  const rec = {
    schema: 'atlas-eidas-certificate-v1', type, serial_sha256: sha256(serial), issuer,
    not_before: new Date(notBefore).toISOString(), not_after: new Date(notAfter).toISOString(),
    private_key_exportable: false,
    signing_boundary: String(input.signing_boundary || 'HSM_OR_KMS'),
    status: String(input.status || 'PENDING')
  };
  rec.record_sha256 = sha256(JSON.stringify(rec));
  return Object.freeze(rec);
}

function evaluateCertificatePair({ qwac, qseal, now = new Date() }) {
  const blockers = [];
  for (const [name, cert] of [['QWAC', qwac], ['QSEAL', qseal]]) {
    if (!cert || cert.type !== name) { blockers.push(`${name}_MISSING`); continue; }
    if (Date.parse(cert.not_after) <= now.getTime()) blockers.push(`${name}_EXPIRED`);
    if (cert.status !== 'ACTIVE') blockers.push(`${name}_NOT_ACTIVE`);
    if (cert.private_key_exportable !== false) blockers.push(`${name}_KEY_BOUNDARY_INVALID`);
  }
  return { schema: 'atlas-eidas-pair-readiness-v1', state: blockers.length ? 'BLOCKED' : 'READY', blockers };
}

module.exports = { certificateRecord, evaluateCertificatePair, sha256 };
