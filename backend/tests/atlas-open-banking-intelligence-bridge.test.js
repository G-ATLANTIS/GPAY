'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { normalizeIntent } = require('../../scripts/atlas-open-banking-core');
const { bridgeRouteDecision, verifyAttestation, sha256 } = require('../../scripts/atlas-open-banking-intelligence-bridge');

function intent() {
  return normalizeIntent({
    intent_id: 'test-intent', amount_in_minor: 29_490_000, currency: 'EUR',
    beneficiary_name: 'Dealer BV', beneficiary_iban_sha256: 'a'.repeat(64),
    reference: 'invoice-1', owner_approval_sha256: 'b'.repeat(64), invoice_sha256: 'c'.repeat(64)
  });
}

function attestation(bound, overrides = {}) {
  const out = {
    schema: 'atlas-payment-rail-intelligence-attestation-v1', version: '1.0.0', status: 'ADVISORY_ONLY_FAIL_CLOSED',
    generated_at: new Date().toISOString(), subject_node: 'GPAY', target_amount_in_minor: bound.amount_in_minor,
    currency: 'EUR', intent_binding_sha256: bound.intent_binding_sha256,
    advisory_preferred_rail_id: 'yapily-connect',
    candidates: [{ rail_id: 'yapily-connect', blockers: [], execution_ready_from_evidence: true }],
    mesh_context: { routed_nodes: ['BANKING'], leverage_score: 1 },
    execution_authorized: false, provider_call_permitted: false, value_moved: false,
    reality_boundary: 'INTELLIGENCE_MAY_ADVISE_BUT_NEVER_AUTHORIZE_OR_EXECUTE_PAYMENT',
    ...overrides
  };
  out.attestation_sha256 = sha256(out);
  return out;
}

function route(bound) {
  return {
    schema: 'atlas-open-banking-route-v1', intent_binding_sha256: bound.intent_binding_sha256,
    selected_adapter_id: 'yapily-connect', selected_adapter_type: 'SPONSORED_PISP', decision: 'EXECUTION_CANDIDATE',
    evaluated: [{ adapter_id: 'yapily-connect', adapter_type: 'SPONSORED_PISP', blockers: [] }],
    provider_call_permitted: false, value_moved: false
  };
}

test('valid intelligence may converge but never authorize', () => {
  const bound = intent();
  const result = bridgeRouteDecision({ routeDecision: route(bound), attestation: attestation(bound), intent: bound });
  assert.equal(result.intelligence_valid, true);
  assert.equal(result.converged_with_core, true);
  assert.equal(result.final_execution_authority, 'GPAY_CORE_ONLY');
  assert.equal(result.provider_call_permitted, false);
  assert.equal(result.value_moved, false);
});

test('amount mismatch fails intelligence verification', () => {
  const bound = intent();
  const a = attestation(bound, { target_amount_in_minor: 100 });
  const result = verifyAttestation({ attestation: a, intent: bound });
  assert.equal(result.valid, false);
  assert.ok(result.blockers.includes('INTELLIGENCE_AMOUNT_MISMATCH'));
});

test('intelligence authority escalation is rejected', () => {
  const bound = intent();
  const a = attestation(bound, { execution_authorized: true });
  const result = verifyAttestation({ attestation: a, intent: bound });
  assert.ok(result.blockers.includes('INTELLIGENCE_AUTHORITY_BOUNDARY_VIOLATION'));
});

test('unknown preferred rail cannot converge', () => {
  const bound = intent();
  const a = attestation(bound, { advisory_preferred_rail_id: 'unknown-rail', candidates: [] });
  const result = bridgeRouteDecision({ routeDecision: route(bound), attestation: a, intent: bound });
  assert.equal(result.converged_with_core, false);
  assert.ok(result.intelligence_blockers.includes('INTELLIGENCE_PREFERRED_RAIL_NOT_IN_CORE_ROUTE_SET'));
});
