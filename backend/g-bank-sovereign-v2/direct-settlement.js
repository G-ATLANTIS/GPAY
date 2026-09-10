'use strict';

const { canonicalJson, sha256 } = require('../g-bank-live-v1/canonical');
const { assertSha256 } = require('./compliance');

class DirectSettlementAdapter {
  constructor({ transport, env = process.env, name = 'g-direct-settlement' } = {}) {
    if (!transport || typeof transport.preflight !== 'function' || typeof transport.submit !== 'function' || typeof transport.readback !== 'function') {
      throw new Error('settlement_transport_invalid');
    }
    this.transport = transport;
    this.env = env;
    this.name = name;
  }

  _requireEnabled() {
    if (this.env.G_BANK_DIRECT_SETTLEMENT_ENABLED !== 'true') throw new Error('direct_settlement_disabled');
    if (this.env.G_BANK_ENABLE_LIVE !== 'true') throw new Error('g_bank_live_execution_disabled');
    if (this.env.G_BANK_EXTERNAL_ACTIONS_ENABLED !== 'true') throw new Error('g_bank_external_actions_disabled');
    if (this.env.G_BANK_SIMULATED_LIVE_SUCCESS === 'true') throw new Error('simulated_live_success_forbidden');
    const auth = String(this.env.G_BANK_SETTLEMENT_AUTHORIZATION_SHA256 || '').toLowerCase();
    assertSha256('settlement_authorization_sha256', auth);
    return auth;
  }

  async preflight() {
    const authorization_sha256 = this._requireEnabled();
    const result = await this.transport.preflight();
    if (!result || result.environment !== 'LIVE' || result.authenticated !== true || result.connected !== true) {
      throw new Error('direct_settlement_preflight_not_verified');
    }
    if (!['SCT', 'SCT_INST'].includes(result.scheme)) throw new Error('direct_settlement_scheme_invalid');
    if (!result.external_receipt_sha256) throw new Error('direct_settlement_preflight_receipt_required');
    assertSha256('settlement_preflight_receipt_sha256', result.external_receipt_sha256);
    return Object.freeze({
      provider: this.name,
      environment: 'LIVE',
      authenticated: true,
      connected: true,
      scheme: result.scheme,
      settlement_system: result.settlement_system || null,
      external_receipt_sha256: result.external_receipt_sha256,
      authorization_sha256,
      provider_http_status: result.provider_http_status ?? null,
      payment_message_submitted: false,
      value_moved: false,
    });
  }

  async submit({ message, instruction, idempotencyKey }) {
    const authorization_sha256 = this._requireEnabled();
    if (!message?.document || !message?.document_sha256) throw new Error('settlement_message_required');
    if (!instruction?.instruction_sha256) throw new Error('settlement_instruction_required');
    if (!idempotencyKey) throw new Error('settlement_idempotency_key_required');

    const response = await this.transport.submit({
      message_type: message.message_type,
      message_document: message.document,
      message_sha256: message.document_sha256,
      instruction,
      idempotency_key: idempotencyKey,
      authorization_sha256,
    });
    if (!response?.submission_id) throw new Error('settlement_submission_id_missing');
    if (!response?.external_receipt_sha256) throw new Error('settlement_submission_receipt_missing');
    assertSha256('settlement_submission_receipt_sha256', response.external_receipt_sha256);

    const receipt = {
      schema: 'g-bank-direct-settlement-submission/v2',
      provider: this.name,
      environment: 'LIVE',
      submission_id: String(response.submission_id),
      status: String(response.status || 'SUBMITTED'),
      message_type: message.message_type,
      message_sha256: message.document_sha256,
      instruction_sha256: instruction.instruction_sha256,
      external_receipt_sha256: response.external_receipt_sha256,
      provider_request_id: response.provider_request_id || null,
      observed_at: new Date().toISOString(),
    };
    receipt.receipt_sha256 = sha256(canonicalJson(receipt));
    return Object.freeze(receipt);
  }

  async readback(submissionId) {
    this._requireEnabled();
    const result = await this.transport.readback(String(submissionId));
    if (!result?.external_receipt_sha256) throw new Error('settlement_readback_receipt_missing');
    assertSha256('settlement_readback_receipt_sha256', result.external_receipt_sha256);
    const status = String(result.status || 'UNKNOWN').toUpperCase();
    if (!['SUBMITTED', 'ACCEPTED', 'SETTLED', 'REJECTED', 'UNKNOWN'].includes(status)) {
      throw new Error('settlement_readback_status_invalid');
    }
    return Object.freeze({
      provider: this.name,
      environment: 'LIVE',
      submission_id: String(submissionId),
      status,
      settlement_reference: result.settlement_reference || null,
      external_receipt_sha256: result.external_receipt_sha256,
      provider_request_id: result.provider_request_id || null,
      observed_at: result.observed_at || new Date().toISOString(),
    });
  }
}

module.exports = { DirectSettlementAdapter };
