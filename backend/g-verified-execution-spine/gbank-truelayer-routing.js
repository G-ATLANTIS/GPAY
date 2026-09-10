'use strict';

// Shared wiring so every live TrueLayer mutation — the HTTP route
// (backend/routes/openbanking.js POST /create-payment) and any operator tool —
// is constructed identically and can only reach the provider through
// executeVerified() + TrueLayerSpineConnector.

const { CapabilityRegistry } = require('./capability-registry');
const { PolicyEngine } = require('./policy');
const { TrueLayerSpineConnector } = require('./connectors/truelayer-spine-connector');
const { normalizeRequest, requestCanonicalSha256 } = require('./spine');
const { sha256 } = require('../g-bank-live-v1/canonical');

const TRUELAYER_CAPABILITY = 'gbank.truelayer.payment';
const TRUELAYER_OPERATION = 'create-payment';

function buildTrueLayerRegistry({ adapter, env = process.env } = {}) {
  const registry = new CapabilityRegistry();
  registry.register(new TrueLayerSpineConnector({ adapter, env }));
  return registry;
}

function buildTrueLayerPolicy({ actor, maxAmountMinor } = {}) {
  if (!actor) throw new Error('truelayer_policy_actor_required');
  const max = Number(maxAmountMinor);
  if (!Number.isSafeInteger(max) || max <= 0) throw new Error('truelayer_policy_max_amount_invalid');
  return new PolicyEngine([
    {
      id: 'gbank-truelayer-allow',
      effect: 'ALLOW',
      match: {
        actor,
        capability: TRUELAYER_CAPABILITY,
        operation: TRUELAYER_OPERATION,
        min_assurance: 'L2', // authenticated + signature-accepted preflight required
        max_amount_minor: max,
        require_scope_bounded: true,
      },
    },
  ]);
}

// input: {
//   actor, requestId, idempotencyKey, expectedSequence, environment,
//   amountMinor, currency, beneficiary:{iban,name,reference},
//   user:{...}, returnUri
// }
function buildTrueLayerRequest(input) {
  const beneficiary = input.beneficiary || {};
  const ibanNorm = String(beneficiary.iban || '').replace(/\s+/g, '').toUpperCase();
  // destination_binding must not embed raw PII — it lands unredacted in audit
  // evidence. Bind to a hash of the counterparty instead.
  const destinationBinding = [
    'truelayer',
    String(input.environment || 'sandbox').toLowerCase(),
    sha256(ibanNorm),
    sha256(String(beneficiary.reference || '').slice(0, 18)),
  ].join(':');

  return {
    request_id: String(input.requestId),
    actor: String(input.actor),
    requested_capability: TRUELAYER_CAPABILITY,
    operation: TRUELAYER_OPERATION,
    params: {
      amount_minor: Number(input.amountMinor),
      currency: String(input.currency || 'EUR'),
      environment: String(input.environment || 'sandbox').toLowerCase(),
      beneficiary: {
        // Keys chosen so redaction.js masks the PII (iban / *holder_name*) in
        // audit evidence while the connector still receives real values.
        iban: String(beneficiary.iban || '').replace(/\s+/g, '').toUpperCase(),
        account_holder_name: String(beneficiary.name || ''),
        reference: String(beneficiary.reference || '').slice(0, 18),
      },
      user: normalizeUser(input.user || {}),
      return_uri: String(input.returnUri || ''),
      destination_binding: destinationBinding,
      beneficiary_iban_sha256: sha256(String(beneficiary.iban || '').replace(/\s+/g, '').toUpperCase()),
      intent_id: input.requestId ? `tl-${input.requestId}` : undefined,
    },
    idempotency_key: String(input.idempotencyKey),
    expected_sequence: Number(input.expectedSequence),
    scope: { max_effects: 1, amount_minor: Number(input.amountMinor), note: 'single bounded truelayer payment create' },
    required_assurance: 'L2',
  };
}

// Map raw user input onto keys that redaction.js masks in evidence
// (full_name / email / phone / date_of_birth / address_line*).
function normalizeUser(user) {
  const a = user.address || {};
  return {
    full_name: String(user.name || ''),
    email: String(user.email || ''),
    phone: String(user.phone || ''),
    date_of_birth: String(user.date_of_birth || ''),
    address: {
      address_line1: String(a.address_line1 || ''),
      ...(a.address_line2 ? { address_line2: String(a.address_line2) } : {}),
      city: String(a.city || ''),
      ...(a.state ? { state: String(a.state) } : {}),
      zip: String(a.zip || ''),
      country_code: String(a.country_code || '').toUpperCase(),
    },
  };
}

function truelayerBindingSha256(request) {
  return requestCanonicalSha256(normalizeRequest(request));
}

module.exports = {
  TRUELAYER_CAPABILITY,
  TRUELAYER_OPERATION,
  buildTrueLayerRegistry,
  buildTrueLayerPolicy,
  buildTrueLayerRequest,
  truelayerBindingSha256,
};
