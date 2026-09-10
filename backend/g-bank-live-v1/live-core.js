'use strict';

const path = require('node:path');
const { normalizeIntent, canonicalJson, sha256 } = require('./canonical');
const { verifyApproval } = require('./approval');
const { IdempotencyStore } = require('./idempotency-store');
const { ReceiptLedger } = require('./receipt-ledger');

function requireLiveExecution(env = process.env) {
  if (env.G_BANK_ENABLE_LIVE !== 'true') throw new Error('g_bank_live_execution_disabled');
  if (env.G_BANK_EXTERNAL_ACTIONS_ENABLED !== 'true') throw new Error('g_bank_external_actions_disabled');
  if (env.G_BANK_SIMULATED_LIVE_SUCCESS === 'true') throw new Error('simulated_live_success_forbidden');
  return true;
}

class GBankLiveCore {
  constructor({ adapters, stateDir = '.secrets/g-bank-live-state', env = process.env } = {}) {
    this.adapters = new Map(Object.entries(adapters || {}));
    this.env = env;
    const root = path.resolve(stateDir);
    this.idempotency = new IdempotencyStore(path.join(root, 'idempotency'));
    this.ledger = new ReceiptLedger(path.join(root, 'receipts.jsonl'));
  }

  adapter(name) {
    const adapter = this.adapters.get(name);
    if (!adapter) throw new Error('provider_not_registered');
    return adapter;
  }

  async preflight(provider) {
    const adapter = this.adapter(provider);
    const result = await adapter.preflight();
    this.ledger.append({
      event: 'PROVIDER_PREFLIGHT',
      provider,
      outcome: 'VERIFIED_READ_ONLY',
      provider_http_status: result.provider_http_status,
      evidence_sha256: sha256(canonicalJson(result)),
      payment_endpoint_called: false,
      value_moved: false,
    });
    return result;
  }

  async execute({ rawIntent, provider, approvalToken, idempotencyKey }) {
    requireLiveExecution(this.env);
    if (!idempotencyKey) throw new Error('explicit_idempotency_key_required');

    const intent = normalizeIntent(rawIntent);
    const approval = verifyApproval(
      approvalToken,
      { intent, provider, idempotencyKey },
      this.env,
    );
    const adapter = this.adapter(provider);

    // Check an already completed identical request before touching the provider.
    // The approval itself is bound to this exact idempotency key, so it cannot
    // authorize a second execution under a different key.
    const request = {
      schema: 'g-bank-live-execution-request/v1',
      provider,
      intent,
      approval_id: approval.approval_id,
      idempotency_key_sha256: sha256(idempotencyKey),
    };
    const existing = this.idempotency.read(idempotencyKey);
    if (existing) {
      const requestSha = sha256(canonicalJson(request));
      if (existing.request_sha256 !== requestSha) {
        throw new Error('idempotency_key_reused_for_different_request');
      }
      if (existing.state === 'SUCCEEDED') return existing.result;
      throw new Error(`idempotency_request_not_replayable_in_state_${existing.state}`);
    }

    // Fresh provider capability proof. It is read-only and happens before the
    // side-effect claim. A failed preflight cannot create a payment.
    const preflight = await adapter.preflight();
    if (preflight.authenticated !== true || preflight.environment !== 'LIVE') {
      throw new Error('provider_live_preflight_not_verified');
    }

    const claim = this.idempotency.claim({ key: idempotencyKey, request });
    if (!claim.owner) throw new Error(`idempotency_request_not_replayable_in_state_${claim.record.state}`);

    this.ledger.append({
      event: 'LIVE_EXECUTION_AUTHORIZED',
      provider,
      intent_id: intent.intent_id,
      intent_sha256: intent.intent_sha256,
      approval_id: approval.approval_id,
      idempotency_key_sha256: sha256(idempotencyKey),
      amount_minor: intent.amount_minor,
      currency: intent.currency,
      destination_binding_sha256: sha256(intent.destination_binding),
    });

    let created;
    try {
      created = await adapter.createPayment({ intent, idempotencyKey });
    } catch (err) {
      // Any transport ambiguity after POST is quarantined. Never fail over to
      // a second provider automatically because the first provider may have
      // accepted the payment despite the missing local response.
      const finalState = err.provider_http_status
        ? 'FAILED_FINAL'
        : 'UNKNOWN_REQUIRES_RECONCILIATION';
      this.idempotency.finalize({
        key: idempotencyKey,
        request,
        state: finalState,
        result: {
          error: err.message,
          provider_http_status: err.provider_http_status || null,
          provider_detail: err.provider_detail || null,
        },
      });
      this.ledger.append({
        event: 'LIVE_EXECUTION_NOT_CONFIRMED',
        provider,
        intent_id: intent.intent_id,
        state: finalState,
        provider_http_status: err.provider_http_status || null,
      });
      throw err;
    }

    if (!created.payment_id) {
      this.idempotency.finalize({
        key: idempotencyKey,
        request,
        state: 'UNKNOWN_REQUIRES_RECONCILIATION',
        result: { error: 'provider_receipt_missing_payment_id' },
      });
      throw new Error('provider_receipt_missing_payment_id');
    }

    let readback;
    try {
      readback = await adapter.getPayment(created.payment_id);
      if (readback.mode && readback.mode !== 'live') throw new Error('provider_readback_not_live');
      if (readback.metadata?.g_intent_sha256 && readback.metadata.g_intent_sha256 !== intent.intent_sha256) {
        throw new Error('provider_readback_intent_binding_mismatch');
      }
    } catch (err) {
      this.idempotency.finalize({
        key: idempotencyKey,
        request,
        state: 'UNKNOWN_REQUIRES_RECONCILIATION',
        result: {
          error: err.message,
          payment_id: created.payment_id,
          provider_http_status: err.provider_http_status || null,
        },
      });
      this.ledger.append({
        event: 'LIVE_WRITE_CREATED_READBACK_UNCERTAIN',
        provider,
        intent_id: intent.intent_id,
        payment_id: created.payment_id,
        state: 'UNKNOWN_REQUIRES_RECONCILIATION',
      });
      throw err;
    }

    const result = {
      schema: 'g-bank-live-execution-result/v1',
      provider,
      environment: 'LIVE',
      intent_id: intent.intent_id,
      intent_sha256: intent.intent_sha256,
      payment_id: created.payment_id,
      checkout_url: created.checkout_url || null,
      provider_status: readback.status || created.status || null,
      provider_create_http_status: created.provider_http_status,
      provider_readback_http_status: readback.provider_http_status,
      idempotency_key_sha256: sha256(idempotencyKey),
      payment_created: true,
      value_moved: readback.status === 'paid',
      verified_write: true,
      verified_value_flow: readback.status === 'paid',
      observed_at: new Date().toISOString(),
    };
    result.result_sha256 = sha256(canonicalJson(result));

    this.idempotency.finalize({ key: idempotencyKey, request, state: 'SUCCEEDED', result });
    this.ledger.append({
      event: 'LIVE_EXECUTION_READBACK_VERIFIED',
      provider,
      intent_id: intent.intent_id,
      payment_id: created.payment_id,
      provider_status: result.provider_status,
      result_sha256: result.result_sha256,
      value_moved: result.value_moved,
    });
    return Object.freeze(result);
  }
}

module.exports = { GBankLiveCore, requireLiveExecution };
