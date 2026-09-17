#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  }
  return value;
}

function sha256(value) {
  return crypto.createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');
}

function verifyAttestation({ attestation, intent, now = new Date(), max_age_seconds = 900 }) {
  if (!attestation || attestation.schema !== 'atlas-payment-rail-intelligence-attestation-v1') {
    throw new Error('intelligence_attestation_schema_invalid');
  }
  if (!intent || !intent.intent_binding_sha256) throw new Error('bound_intent_required');

  const blockers = [];
  if (attestation.subject_node !== 'GPAY') blockers.push('INTELLIGENCE_SUBJECT_MISMATCH');
  if (attestation.currency !== 'EUR') blockers.push('INTELLIGENCE_CURRENCY_MISMATCH');
  if (attestation.target_amount_in_minor !== intent.amount_in_minor) blockers.push('INTELLIGENCE_AMOUNT_MISMATCH');
  if (attestation.intent_binding_sha256 && attestation.intent_binding_sha256 !== intent.intent_binding_sha256) {
    blockers.push('INTELLIGENCE_INTENT_BINDING_MISMATCH');
  }
  if (attestation.execution_authorized !== false || attestation.provider_call_permitted !== false || attestation.value_moved !== false) {
    blockers.push('INTELLIGENCE_AUTHORITY_BOUNDARY_VIOLATION');
  }

  const generated = Date.parse(attestation.generated_at);
  const ageMs = now.getTime() - generated;
  if (!Number.isFinite(generated) || ageMs < -60_000 || ageMs > max_age_seconds * 1000) {
    blockers.push('INTELLIGENCE_ATTESTATION_STALE');
  }

  if (!Array.isArray(attestation.candidates)) blockers.push('INTELLIGENCE_CANDIDATES_REQUIRED');

  if (attestation.attestation_sha256) {
    const copy = { ...attestation };
    delete copy.attestation_sha256;
    if (sha256(copy) !== attestation.attestation_sha256) blockers.push('INTELLIGENCE_ATTESTATION_HASH_MISMATCH');
  } else {
    blockers.push('INTELLIGENCE_ATTESTATION_HASH_REQUIRED');
  }

  return {
    schema: 'atlas-payment-intelligence-verification-v1',
    valid: blockers.length === 0,
    blockers: [...new Set(blockers)].sort()
  };
}

function bridgeRouteDecision({ routeDecision, attestation, intent, now = new Date(), max_age_seconds = 900 }) {
  if (!routeDecision || routeDecision.schema !== 'atlas-open-banking-route-v1') {
    throw new Error('core_route_decision_required');
  }
  const verification = verifyAttestation({ attestation, intent, now, max_age_seconds });
  const preferred = attestation.advisory_preferred_rail_id || null;
  const evaluatedIds = new Set((routeDecision.evaluated || []).map(row => row.adapter_id));
  const intelligenceBlockers = [...verification.blockers];
  if (preferred && !evaluatedIds.has(preferred)) intelligenceBlockers.push('INTELLIGENCE_PREFERRED_RAIL_NOT_IN_CORE_ROUTE_SET');

  const candidate = Array.isArray(attestation.candidates)
    ? attestation.candidates.find(row => row.rail_id === preferred)
    : null;
  if (candidate && Array.isArray(candidate.blockers) && candidate.blockers.length) {
    intelligenceBlockers.push(...candidate.blockers.map(x => `INTELLIGENCE:${x}`));
  }

  const converged = intelligenceBlockers.length === 0
    && preferred !== null
    && routeDecision.selected_adapter_id === preferred;

  return {
    schema: 'atlas-open-banking-intelligence-bridge-v1',
    intent_binding_sha256: intent.intent_binding_sha256,
    core_decision: routeDecision.decision,
    core_selected_adapter_id: routeDecision.selected_adapter_id,
    advisory_preferred_adapter_id: preferred,
    intelligence_valid: verification.valid,
    converged_with_core: converged,
    intelligence_blockers: [...new Set(intelligenceBlockers)].sort(),
    final_execution_authority: 'GPAY_CORE_ONLY',
    provider_call_permitted: false,
    value_moved: false,
    reality_boundary: 'INTELLIGENCE_CANNOT_GRANT_PAYMENT_EXECUTION'
  };
}

module.exports = { bridgeRouteDecision, verifyAttestation, sha256 };
