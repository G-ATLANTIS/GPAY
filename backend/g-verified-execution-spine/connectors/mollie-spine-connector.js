'use strict';

const { sha256 } = require('../../g-bank-live-v1/canonical');
const { MollieLiveAdapter } = require('../../g-bank-live-v1/providers/mollie-live');
const { requireLiveExecution } = require('../../g-bank-live-v1/live-core');

// Routes the pre-existing, independently reviewed Mollie LIVE adapter
// (backend/g-bank-live-v1/providers/mollie-live.js) through the canonical
// spine. No payment logic is reimplemented here — this is an adapter shim that
// maps the spine connector contract onto the adapter's
// preflight()/createPayment()/getPayment().
//
// It stays fail-closed: discover() and execute() both re-assert
// requireLiveExecution(env) AND the spine-level allowExternalEffects flag, so
// this connector is inert in tests and in any process that has not explicitly
// opted into live external effects.

function buildIntent(params) {
  // The spine's `params` for a Mollie payment operation.
  const p = params || {};
  return {
    intent_id: String(p.intent_id || ''),
    amount_minor: Number(p.amount_minor),
    currency: String(p.currency || ''),
    description: String(p.description || ''),
    destination_binding: String(p.destination_binding || ''),
    redirect_url: p.redirect_url || null,
    webhook_url: p.webhook_url || null,
    metadata: p.metadata && typeof p.metadata === 'object' ? p.metadata : {},
    intent_sha256: p.intent_sha256 || null,
  };
}

class MollieSpineConnector {
  constructor({ adapter, env = process.env } = {}) {
    this.name = 'gbank.mollie.payment';
    this.assurance_ceiling = 'L4';
    this.supportsReadback = true;
    this.env = env;
    this.adapter = adapter || new MollieLiveAdapter({ apiKey: env.MOLLIE_API_KEY });
  }

  _assertLive(allowExternalEffects) {
    if (allowExternalEffects !== true) throw new Error('external_effects_not_enabled_for_process');
    requireLiveExecution(this.env); // throws unless G_BANK_ENABLE_LIVE etc. set
  }

  async discover({ allowExternalEffects } = {}) {
    try {
      this._assertLive(allowExternalEffects);
    } catch (err) {
      return { ok: false, observed_assurance: 'L0', detail: err.message };
    }
    try {
      const pf = await this.adapter.preflight(); // read-only GET
      if (pf.authenticated !== true || pf.environment !== 'LIVE') {
        return { ok: false, observed_assurance: 'L0', detail: 'preflight_not_live_authenticated' };
      }
      // Authenticated external read verified.
      return { ok: true, observed_assurance: 'L2', detail: 'mollie live preflight ok' };
    } catch (err) {
      return { ok: false, observed_assurance: 'L0', detail: `preflight_failed:${err.message}` };
    }
  }

  async captureState({ params } = {}) {
    // No cheap global state hash for a PSP; bind to the intent identity so
    // pre/post differ only by the created payment.
    const intent = buildIntent(params);
    return sha256(`mollie-intent:${intent.intent_id}:${intent.intent_sha256 || 'nil'}`);
  }

  async execute({ params, idempotency_key, allowExternalEffects }) {
    this._assertLive(allowExternalEffects);
    const intent = buildIntent(params);
    const created = await this.adapter.createPayment({ intent, idempotencyKey: idempotency_key });
    if (!created.payment_id) {
      throw new Error('provider_receipt_missing_payment_id');
    }
    return {
      provider: this.name,
      provider_request_id: created.payment_id,
      receipt: {
        payment_id: created.payment_id,
        status: created.status || null,
        mode: created.mode || null,
        checkout_url: created.checkout_url || null,
        provider_http_status: created.provider_http_status,
      },
      applied: true,
      raw_status: created.status || null,
    };
  }

  // L4 requires strong evidence that the read-back payment IS the one this
  // execution created. A bare "GET payment succeeded" is not enough.
  //
  //   binding_ok    = every binding field that IS present matches. Any positive
  //                   mismatch (wrong id / amount / currency / intent hash /
  //                   destination / non-live mode) -> false -> READBACK_MISMATCH.
  //   binding_strength = 'STRONG' only when payment id + live mode + amount +
  //                   currency + intent-hash + destination-binding are all
  //                   present and all match. Otherwise 'WEAK' -> the spine caps
  //                   assurance at L3 and marks verification PROVIDER_RECEIPT_ONLY.
  async readback({ params, binding_sha256 }, exec) {
    const paymentId = exec && exec.provider_request_id;
    if (!paymentId) {
      return { verified: false, binding_ok: false, observed_status: 'NO_PAYMENT_ID', external: true, binding_strength: 'WEAK' };
    }
    const readback = await this.adapter.getPayment(paymentId);

    // Reconcile mode: confirm on the non-PII strong triplet (payment id + live
    // mode + canonical request hash in metadata); redacted params can't be
    // re-compared.
    if (params && params.reconcile === true) {
      const idOk = readback.payment_id === paymentId;
      const live = !readback.mode || readback.mode === 'live';
      const storedHash = readback.metadata && readback.metadata.g_intent_sha256;
      const hashOk = !storedHash
        ? null
        : storedHash === binding_sha256 || storedHash === params.intent_sha256;
      return {
        verified: idOk && live,
        binding_ok: idOk && live && hashOk !== false,
        binding_strength: hashOk === true ? 'STRONG' : 'WEAK',
        observed_status: readback.status || (idOk ? 'FOUND' : 'NOT_FOUND'),
        external: true,
        provider_request_id: readback.payment_id || null,
        detail: { reconcile: true, id_ok: idOk, live, hash_ok: hashOk },
      };
    }
    const intent = buildIntent(params);

    const checks = {};
    const mismatch = [];

    // Payment identity — mandatory.
    checks.payment_id = readback.payment_id === paymentId;
    if (readback.payment_id && !checks.payment_id) mismatch.push('payment_id');

    // Live mode — mandatory and strict (absent mode is NOT treated as live).
    checks.live_mode = readback.mode === 'live';
    if (readback.mode && readback.mode !== 'live') mismatch.push('mode');

    // Amount + currency.
    const expectedValue = Number.isFinite(intent.amount_minor)
      ? (intent.amount_minor / 100).toFixed(2)
      : null;
    if (readback.amount && expectedValue !== null) {
      checks.amount = String(readback.amount.value) === expectedValue;
      checks.currency = String(readback.amount.currency) === intent.currency;
      if (!checks.amount) mismatch.push('amount');
      if (!checks.currency) mismatch.push('currency');
    } else {
      checks.amount = false;
      checks.currency = false;
    }

    // Intent hash + destination binding persisted in provider metadata.
    const md = readback.metadata || {};
    if (intent.intent_sha256 && md.g_intent_sha256) {
      checks.intent_sha256 = md.g_intent_sha256 === intent.intent_sha256;
      if (!checks.intent_sha256) mismatch.push('intent_sha256');
    } else {
      checks.intent_sha256 = false;
    }
    if (intent.destination_binding && md.g_destination_binding_sha256) {
      checks.destination_binding = md.g_destination_binding_sha256 === sha256(intent.destination_binding);
      if (!checks.destination_binding) mismatch.push('destination_binding');
    } else {
      checks.destination_binding = false;
    }

    const mandatoryOk = checks.payment_id && checks.live_mode;
    const strong =
      mandatoryOk &&
      checks.amount &&
      checks.currency &&
      checks.intent_sha256 &&
      checks.destination_binding;

    return {
      verified: mandatoryOk && !!readback.payment_id,
      binding_ok: mismatch.length === 0 && mandatoryOk,
      binding_strength: strong ? 'STRONG' : 'WEAK',
      observed_status: readback.status || null,
      external: true, // authenticated external readback
      detail: { mode: readback.mode || null, checks, mismatch },
    };
  }
}

module.exports = { MollieSpineConnector };
