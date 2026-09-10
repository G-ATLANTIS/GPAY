'use strict';

// Shared wiring so EVERY live Mollie mutation — the operator CLI
// (scripts/g-bank-live-v1.js) and the HTTP route (backend/routes/mollie.js) —
// is constructed identically and can only reach the provider through
// executeVerified() + MollieSpineConnector.

const { CapabilityRegistry } = require('./capability-registry');
const { PolicyEngine } = require('./policy');
const { MollieSpineConnector } = require('./connectors/mollie-spine-connector');
const { normalizeRequest, requestCanonicalSha256 } = require('./spine');

const MOLLIE_CAPABILITY = 'gbank.mollie.payment';
const MOLLIE_OPERATION = 'create-payment';

function buildMollieRegistry({ adapter, env = process.env } = {}) {
  const registry = new CapabilityRegistry();
  registry.register(new MollieSpineConnector({ adapter, env }));
  return registry;
}

function buildMolliePolicy({ actor, maxAmountMinor } = {}) {
  if (!actor) throw new Error('mollie_policy_actor_required');
  const max = Number(maxAmountMinor);
  if (!Number.isSafeInteger(max) || max <= 0) throw new Error('mollie_policy_max_amount_invalid');
  return new PolicyEngine([
    // Kill switch: an operator can hard-stop the capability by setting this
    // rule's guard elsewhere; kept explicit so a DENY is always expressible.
    {
      id: 'gbank-mollie-allow',
      effect: 'ALLOW',
      match: {
        actor,
        capability: MOLLIE_CAPABILITY,
        operation: MOLLIE_OPERATION,
        min_assurance: 'L2', // authenticated external read must have been evidenced by discover()
        max_amount_minor: max,
        require_scope_bounded: true,
      },
    },
  ]);
}

// intent: { intent_id, amount_minor, currency, description, destination_binding,
//           redirect_url, webhook_url, metadata, intent_sha256? }
function buildMollieRequest({
  actor,
  requestId,
  intent,
  idempotencyKey,
  expectedSequence,
  requiredAssurance = 'L2',
}) {
  const request = {
    request_id: String(requestId),
    actor: String(actor),
    requested_capability: MOLLIE_CAPABILITY,
    operation: MOLLIE_OPERATION,
    params: {
      intent_id: intent.intent_id,
      amount_minor: intent.amount_minor,
      currency: intent.currency,
      description: intent.description,
      destination_binding: intent.destination_binding,
      redirect_url: intent.redirect_url || null,
      webhook_url: intent.webhook_url || null,
      metadata: intent.metadata && typeof intent.metadata === 'object' ? intent.metadata : {},
      intent_sha256: intent.intent_sha256 || null,
    },
    idempotency_key: String(idempotencyKey),
    expected_sequence: Number(expectedSequence),
    scope: { max_effects: 1, amount_minor: intent.amount_minor, note: 'single bounded mollie payment create' },
    required_assurance: requiredAssurance,
  };
  return request;
}

function mollieBindingSha256(request) {
  return requestCanonicalSha256(normalizeRequest(request));
}

module.exports = {
  MOLLIE_CAPABILITY,
  MOLLIE_OPERATION,
  buildMollieRegistry,
  buildMolliePolicy,
  buildMollieRequest,
  mollieBindingSha256,
};
