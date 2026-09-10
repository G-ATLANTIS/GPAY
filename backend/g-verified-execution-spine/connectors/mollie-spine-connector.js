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
        provider_http_status: created.provider_http_status,
      },
      applied: true,
      raw_status: created.status || null,
    };
  }

  async readback({ params }, exec) {
    const paymentId = exec && exec.provider_request_id;
    const readback = await this.adapter.getPayment(paymentId);
    const intent = buildIntent(params);
    const bindingOk =
      !readback.metadata ||
      !readback.metadata.g_intent_sha256 ||
      !intent.intent_sha256 ||
      readback.metadata.g_intent_sha256 === intent.intent_sha256;
    const live = !readback.mode || readback.mode === 'live';
    return {
      verified: live && !!readback.payment_id,
      binding_ok: bindingOk,
      observed_status: readback.status || null,
      external: true, // authenticated external readback
      detail: { mode: readback.mode || null },
    };
  }
}

module.exports = { MollieSpineConnector };
