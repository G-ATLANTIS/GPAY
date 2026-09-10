'use strict';

const { sha256 } = require('../../g-bank-live-v1/canonical');
const { TrueLayerLiveAdapter } = require('../../g-bank-live-v1/providers/truelayer-live');
const { requireLiveExecution } = require('../../g-bank-live-v1/live-core');

// Routes TrueLayer v3 payment creation through G_VERIFIED_EXECUTION_SPINE.
// TrueLayer-specific behaviour only: request-body shape, provider preflight,
// and readback binding classification. Generic policy / authorization /
// idempotency / sequencing / audit / assurance are the spine's.
//
// Fail-closed: discover() and execute() both re-assert requireLiveExecution(env)
// AND the spine-level allowExternalEffects flag; inert otherwise.

function allowedBeneficiaryIbans(env) {
  return String((env || process.env).G_BANK_ALLOWED_BENEFICIARY_IBANS || '')
    .split(',')
    .map((v) => v.replace(/\s+/g, '').toUpperCase())
    .filter(Boolean);
}

// params: { amount_minor, currency, beneficiary:{iban,name,reference},
//           user:{name,email,phone,date_of_birth,address:{...}},
//           return_uri, environment, destination_binding, intent_sha256 }
function buildPaymentBody(params, bindingSha) {
  const p = params || {};
  const ben = p.beneficiary || {};
  const user = p.user || {};
  const address = user.address || {};
  const live = String(p.environment || '').toLowerCase() === 'live';
  return {
    amount_in_minor: Number(p.amount_minor),
    currency: String(p.currency || 'EUR'),
    payment_method: {
      type: 'bank_transfer',
      provider_selection: {
        type: 'user_selected',
        filter: {
          countries: ['NL'],
          customer_segments: ['retail'],
          ...(live ? {} : { provider_ids: ['mock-payments-nl-redirect'] }),
        },
        scheme_selection: { type: 'user_selected', allow_remitter_fee: false },
      },
      beneficiary: {
        type: 'external_account',
        account_holder_name: String(ben.account_holder_name || ben.name || ''),
        account_identifier: { type: 'iban', iban: String(ben.iban || '') },
        reference: String(ben.reference || '').slice(0, 18),
      },
    },
    hosted_page: { return_uri: String(p.return_uri || ''), country_code: 'NL', language_code: 'nl' },
    user: {
      name: String(user.full_name || user.name || ''),
      email: String(user.email || ''),
      phone: String(user.phone || ''),
      date_of_birth: String(user.date_of_birth || ''),
      address: {
        address_line1: String(address.address_line1 || ''),
        ...(address.address_line2 ? { address_line2: String(address.address_line2) } : {}),
        city: String(address.city || ''),
        ...(address.state ? { state: String(address.state) } : {}),
        zip: String(address.zip || ''),
        country_code: String(address.country_code || '').toUpperCase(),
      },
    },
    metadata: {
      g_bank: 'true',
      g_intent_sha256: String(bindingSha || ''),
      g_destination_binding_sha256: sha256(String(p.destination_binding || '')),
    },
  };
}

class TrueLayerSpineConnector {
  constructor({ adapter, env = process.env } = {}) {
    this.name = 'gbank.truelayer.payment';
    this.assurance_ceiling = 'L4';
    this.supportsReadback = true;
    this.env = env;
    this.adapter = adapter || new TrueLayerLiveAdapter({ env });
  }

  _assertLive(allowExternalEffects) {
    if (allowExternalEffects !== true) throw new Error('external_effects_not_enabled_for_process');
    requireLiveExecution(this.env);
  }

  _expectedEnvironment() {
    return String(this.env.TRUELAYER_ENV || 'sandbox').toLowerCase() === 'live' ? 'LIVE' : 'SANDBOX';
  }

  async discover({ allowExternalEffects } = {}) {
    try {
      this._assertLive(allowExternalEffects);
    } catch (err) {
      return { ok: false, observed_assurance: 'L0', detail: err.message };
    }
    try {
      const pf = await this.adapter.preflight(); // OAuth token + signed /test-signature (no side effect)
      if (pf.authenticated !== true || pf.signature_accepted !== true) {
        return { ok: false, observed_assurance: 'L0', detail: `preflight_not_ready:${pf.provider_http_status}` };
      }
      return { ok: true, observed_assurance: 'L2', detail: `truelayer ${pf.environment} preflight ok` };
    } catch (err) {
      return { ok: false, observed_assurance: 'L0', detail: `preflight_failed:${err.message}` };
    }
  }

  async captureState({ params } = {}) {
    const p = params || {};
    return sha256(`truelayer-intent:${p.intent_id || 'nil'}:${p.intent_sha256 || 'nil'}`);
  }

  async execute({ params, idempotency_key, binding_sha256, allowExternalEffects }) {
    this._assertLive(allowExternalEffects);
    const iban = String((params && params.beneficiary && params.beneficiary.iban) || '').replace(/\s+/g, '').toUpperCase();
    const allow = allowedBeneficiaryIbans(this.env);
    if (this._expectedEnvironment() === 'LIVE' && allow.length > 0 && !allow.includes(iban)) {
      const err = new Error('beneficiary_not_in_live_allowlist');
      err.provider_http_status = 422; // definite refusal, no provider call made
      throw err;
    }
    const body = buildPaymentBody(params, binding_sha256);
    const created = await this.adapter.createPayment({ body, idempotencyKey: idempotency_key });
    if (!created.payment_id) throw new Error('provider_receipt_missing_payment_id');
    return {
      provider: this.name,
      provider_request_id: created.payment_id,
      receipt: {
        payment_id: created.payment_id,
        status: created.status || null,
        environment: created.environment || null,
        authorization_url: created.authorization_url || null,
        provider_http_status: created.provider_http_status,
        idempotent_replayed: created.idempotent_replayed === true,
      },
      applied: true,
      raw_status: created.status || null,
    };
  }

  async readback({ params, binding_sha256 }, exec) {
    const paymentId = exec && exec.provider_request_id;
    if (!paymentId) {
      return { verified: false, binding_ok: false, observed_status: 'NO_PAYMENT_ID', external: true, binding_strength: 'WEAK' };
    }
    const rb = await this.adapter.getPayment(paymentId);
    const p = params || {};
    const ben = p.beneficiary || {};

    // Reconcile mode: params were reconstructed from redacted evidence, so the
    // PII fields (iban / reference) cannot be re-compared. Confirm on the
    // non-PII strong triplet: payment id + environment + canonical request hash
    // persisted in provider metadata.
    if (p.reconcile === true) {
      const idOk = rb.payment_id === paymentId;
      const envOk = rb.environment === this._expectedEnvironment();
      const md = rb.metadata || {};
      const storedHash = md.g_intent_sha256;
      const hashOk = !storedHash ? null : storedHash === binding_sha256 || storedHash === p.intent_sha256;
      const bindingOk = idOk && envOk && hashOk !== false;
      return {
        verified: idOk && envOk,
        binding_ok: bindingOk,
        binding_strength: hashOk === true ? 'STRONG' : 'WEAK',
        observed_status: rb.status || (idOk ? 'FOUND' : 'NOT_FOUND'),
        external: true,
        provider_request_id: rb.payment_id || null,
        detail: { environment: rb.environment || null, reconcile: true, id_ok: idOk, env_ok: envOk, hash_ok: hashOk },
      };
    }

    const checks = {};
    const mismatch = [];

    checks.payment_id = rb.payment_id === paymentId;
    if (rb.payment_id && !checks.payment_id) mismatch.push('payment_id');

    checks.environment = rb.environment === this._expectedEnvironment();
    if (rb.environment && !checks.environment) mismatch.push('environment');

    if (typeof rb.amount_in_minor === 'number' && Number.isFinite(Number(p.amount_minor))) {
      checks.amount = rb.amount_in_minor === Number(p.amount_minor);
      if (!checks.amount) mismatch.push('amount');
    } else {
      checks.amount = false;
    }

    if (rb.currency && p.currency) {
      checks.currency = String(rb.currency).toUpperCase() === String(p.currency).toUpperCase();
      if (!checks.currency) mismatch.push('currency');
    } else {
      checks.currency = false;
    }

    if (rb.beneficiary_iban && ben.iban) {
      checks.beneficiary_iban =
        String(rb.beneficiary_iban).replace(/\s+/g, '').toUpperCase() ===
        String(ben.iban).replace(/\s+/g, '').toUpperCase();
      if (!checks.beneficiary_iban) mismatch.push('beneficiary_iban');
    } else {
      checks.beneficiary_iban = false;
    }

    if (rb.beneficiary_reference && ben.reference) {
      checks.beneficiary_reference = String(rb.beneficiary_reference) === String(ben.reference).slice(0, 18);
      if (!checks.beneficiary_reference) mismatch.push('beneficiary_reference');
    } else {
      checks.beneficiary_reference = false;
    }

    const md = rb.metadata || {};
    if (binding_sha256 && md.g_intent_sha256) {
      checks.intent_sha256 = md.g_intent_sha256 === binding_sha256;
      if (!checks.intent_sha256) mismatch.push('intent_sha256');
    } else {
      checks.intent_sha256 = false;
    }
    if (p.destination_binding && md.g_destination_binding_sha256) {
      checks.destination_binding = md.g_destination_binding_sha256 === sha256(String(p.destination_binding));
      if (!checks.destination_binding) mismatch.push('destination_binding');
    } else {
      checks.destination_binding = false;
    }

    const mandatoryOk = checks.payment_id && checks.environment;
    const strong =
      mandatoryOk &&
      checks.amount &&
      checks.currency &&
      checks.beneficiary_iban &&
      checks.beneficiary_reference &&
      checks.intent_sha256 &&
      checks.destination_binding;

    return {
      verified: mandatoryOk && !!rb.payment_id,
      binding_ok: mismatch.length === 0 && mandatoryOk,
      binding_strength: strong ? 'STRONG' : 'WEAK',
      observed_status: rb.status || null,
      external: true,
      provider_request_id: rb.payment_id || null,
      detail: { environment: rb.environment || null, checks, mismatch },
    };
  }
}

module.exports = { TrueLayerSpineConnector, buildPaymentBody, allowedBeneficiaryIbans };
