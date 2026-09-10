'use strict';

const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');
const { SovereignReceiptLedger } = require('./receipt-ledger');
const { normalizeInstruction } = require('./instruction');
const { buildPacs008 } = require('./iso20022');
const { verifyComplianceBundle } = require('./compliance');
const { verifySchemeValidationEvidence } = require('./scheme-validation');
const { verifySovereignApproval } = require('./approval');
const { createGovernanceProof } = require('./governance');
const { SovereignExecutionStore } = require('./execution-store');

function requireSovereignLive(env = process.env) {
  if (env.G_BANK_ENABLE_LIVE !== 'true') throw new Error('g_bank_live_execution_disabled');
  if (env.G_BANK_EXTERNAL_ACTIONS_ENABLED !== 'true') throw new Error('g_bank_external_actions_disabled');
  if (env.G_BANK_DIRECT_SETTLEMENT_ENABLED !== 'true') throw new Error('direct_settlement_disabled');
  if (env.G_BANK_GOVERNANCE_REQUIRED !== 'true') throw new Error('sovereign_governance_must_be_required');
  if (env.G_BANK_SIMULATED_LIVE_SUCCESS === 'true') throw new Error('simulated_live_success_forbidden');
  return true;
}

function verifyPrepared(prepared) {
  if (!prepared || prepared.schema !== 'g-bank-sovereign-prepared-payment/v2') throw new Error('prepared_payment_invalid');
  if (prepared.iso20022?.document_sha256 !== sha256(prepared.iso20022?.document || '')) throw new Error('prepared_message_hash_invalid');
  const { preparation_sha256, ...body } = prepared;
  if (preparation_sha256 !== sha256(canonicalJson(body))) throw new Error('prepared_payment_hash_invalid');
  return true;
}

class GBankSovereignCore {
  constructor({ accounts, ledger, settlement, riskPolicy, authoritySet, stateDir = '.secrets/g-bank-sovereign-v2', env = process.env } = {}) {
    if (!accounts || !ledger || !settlement || !riskPolicy || !authoritySet) throw new Error('sovereign_core_dependencies_required');
    this.accounts = accounts;
    this.ledger = ledger;
    this.settlement = settlement;
    this.riskPolicy = riskPolicy;
    this.authoritySet = authoritySet;
    this.env = env;
    const root = path.resolve(stateDir);
    this.executions = new SovereignExecutionStore(path.join(root, 'executions'));
    this.receipts = new SovereignReceiptLedger(path.join(root, 'receipts.jsonl'));
  }

  _systemAccounts(currency) {
    const suspense = this.env.G_BANK_OUTBOUND_SUSPENSE_ACCOUNT || 'G:SUSPENSE:OUTBOUND';
    const settlementOut = this.env.G_BANK_SETTLEMENT_OUT_ACCOUNT || 'G:SETTLEMENT:OUTBOUND';
    this.accounts.requireActive(suspense, currency);
    this.accounts.requireActive(settlementOut, currency);
    return { suspense, settlementOut };
  }

  prepare({ rawInstruction, complianceBundle, now = Date.now() }) {
    const withBankBic = {
      ...rawInstruction,
      debtor_agent_bic: rawInstruction?.debtor_agent_bic || this.env.G_BANK_BIC,
    };
    const instruction = normalizeInstruction(withBankBic);
    const source = this.accounts.requireActive(instruction.source_account_id, instruction.currency);
    if (!source.iban || source.iban !== instruction.debtor_iban) throw new Error('source_account_debtor_iban_mismatch');
    this._systemAccounts(instruction.currency);

    const complianceProof = verifyComplianceBundle(complianceBundle, { now });
    const iso20022 = buildPacs008({
      ...instruction,
      transaction_id: instruction.instruction_id,
    }, { instant: instruction.scheme === 'SCT_INST', now: new Date(now) });

    const body = {
      schema: 'g-bank-sovereign-prepared-payment/v2',
      instruction,
      compliance_proof: complianceProof,
      iso20022,
      prepared_at: new Date(now).toISOString(),
    };
    const prepared = { ...body, preparation_sha256: sha256(canonicalJson(body)) };
    this.receipts.append({
      event: 'SOVEREIGN_PAYMENT_PREPARED',
      source_account_id: instruction.source_account_id,
      instruction_sha256: instruction.instruction_sha256,
      preparation_sha256: prepared.preparation_sha256,
      message_sha256: iso20022.document_sha256,
      compliance_proof_sha256: complianceProof.proof_sha256,
      amount_minor: instruction.amount_minor,
      currency: instruction.currency,
      scheme: instruction.scheme,
      value_moved: false,
    });
    return Object.freeze(prepared);
  }

  _request(prepared, schemeProof, approval, governance) {
    const { suspense, settlementOut } = this._systemAccounts(prepared.instruction.currency);
    return {
      schema: 'g-bank-sovereign-execution-request/v2',
      preparation_sha256: prepared.preparation_sha256,
      instruction_sha256: prepared.instruction.instruction_sha256,
      message_sha256: prepared.iso20022.document_sha256,
      compliance_proof_sha256: prepared.compliance_proof.proof_sha256,
      scheme_validation_proof_sha256: schemeProof.proof_sha256,
      governance_proof_sha256: governance.governance_proof_sha256,
      risk_decision_sha256: governance.risk_decision_sha256,
      policy_sha256: governance.policy_sha256,
      policy_epoch: governance.policy_epoch,
      authority_set_sha256: governance.authority_set_sha256,
      authority_epoch: governance.authority_epoch,
      required_quorum: governance.required_quorum,
      approval_id: approval.approval_id,
      source_account_id: prepared.instruction.source_account_id,
      suspense_account_id: suspense,
      settlement_out_account_id: settlementOut,
      amount_minor: prepared.instruction.amount_minor,
      currency: prepared.instruction.currency,
      scheme: prepared.instruction.scheme,
      beneficiary_binding_sha256: prepared.instruction.beneficiary_binding_sha256,
    };
  }

  _hold({ request, key }) {
    if (this.ledger.balance(request.source_account_id, request.currency) < request.amount_minor) {
      throw new Error('insufficient_available_ledger_balance');
    }
    return this.ledger.post({
      transaction_id: `HOLD-${sha256(String(key)).slice(0, 24)}`,
      reference: request.instruction_sha256,
      entries: [
        { account_id: request.source_account_id, side: 'DEBIT', amount_minor: request.amount_minor, currency: request.currency },
        { account_id: request.suspense_account_id, side: 'CREDIT', amount_minor: request.amount_minor, currency: request.currency },
      ],
      metadata: { kind: 'OUTBOUND_HOLD', preparation_sha256: request.preparation_sha256 },
    });
  }

  _release({ request, key, reason }) {
    const release = this.ledger.post({
      transaction_id: `RELEASE-${sha256(String(key)).slice(0, 24)}`,
      reference: request.instruction_sha256,
      entries: [
        { account_id: request.suspense_account_id, side: 'DEBIT', amount_minor: request.amount_minor, currency: request.currency },
        { account_id: request.source_account_id, side: 'CREDIT', amount_minor: request.amount_minor, currency: request.currency },
      ],
      metadata: { kind: 'OUTBOUND_HOLD_RELEASE', reason },
    });
    this.receipts.append({
      event: 'SOVEREIGN_VALUE_HOLD_RELEASED',
      source_account_id: request.source_account_id,
      instruction_sha256: request.instruction_sha256,
      amount_minor: request.amount_minor,
      currency: request.currency,
      release_record_sha256: release.record_sha256,
      reason,
      value_moved: false,
    });
    return release;
  }

  _bookSettled({ request, key, settlementReference }) {
    return this.ledger.post({
      transaction_id: `SETTLE-${sha256(String(key)).slice(0, 24)}`,
      reference: request.instruction_sha256,
      entries: [
        { account_id: request.suspense_account_id, side: 'DEBIT', amount_minor: request.amount_minor, currency: request.currency },
        { account_id: request.settlement_out_account_id, side: 'CREDIT', amount_minor: request.amount_minor, currency: request.currency },
      ],
      metadata: { kind: 'OUTBOUND_SETTLED', settlement_reference: settlementReference || null },
    });
  }

  _result(request, extra) {
    const body = {
      schema: 'g-bank-sovereign-execution-result/v2',
      instruction_sha256: request.instruction_sha256,
      preparation_sha256: request.preparation_sha256,
      governance_proof_sha256: request.governance_proof_sha256,
      amount_minor: request.amount_minor,
      currency: request.currency,
      scheme: request.scheme,
      ...extra,
      observed_at: new Date().toISOString(),
    };
    return { ...body, result_sha256: sha256(canonicalJson(body)) };
  }

  _existingExecution(idempotencyKey, prepared) {
    const existing = this.executions.read(idempotencyKey);
    if (!existing) return null;
    if (!existing.request || existing.request.preparation_sha256 !== prepared.preparation_sha256) {
      throw new Error('idempotency_key_reused_for_different_preparation');
    }
    if (['SETTLED', 'REJECTED', 'FAILED_FINAL'].includes(existing.state)) return existing.result;
    throw new Error(`execution_exists_${existing.state.toLowerCase()}_use_reconcile`);
  }

  async execute({ prepared, schemeValidationEvidence, approvalToken, authoritySignatures, idempotencyKey, now = Date.now() }) {
    requireSovereignLive(this.env);
    verifyPrepared(prepared);
    if (!idempotencyKey) throw new Error('idempotency_key_required');

    const replay = this._existingExecution(idempotencyKey, prepared);
    if (replay) return replay;

    const schemeProof = verifySchemeValidationEvidence(schemeValidationEvidence, prepared.iso20022, {
      require_external: true,
      now,
    });
    if (schemeProof.scheme !== prepared.instruction.scheme) throw new Error('scheme_validation_scheme_mismatch');

    const governance = createGovernanceProof({
      prepared,
      schemeValidationEvidence,
      idempotencyKey,
      policy: this.riskPolicy,
      authoritySet: this.authoritySet,
      signatures: authoritySignatures,
      receiptRows: this.receipts.readAll(),
      now,
    });
    const approval = verifySovereignApproval(approvalToken, { prepared, schemeValidationEvidence, idempotencyKey, now }, this.env);
    const request = this._request(prepared, schemeProof, approval, governance);

    const preflight = await this.settlement.preflight();
    if (preflight.scheme !== prepared.instruction.scheme) throw new Error('settlement_preflight_scheme_mismatch');

    const claim = this.executions.claim({ key: idempotencyKey, request });
    if (!claim.owner) {
      if (!claim.record.request || claim.record.request.preparation_sha256 !== prepared.preparation_sha256) {
        throw new Error('idempotency_key_reused_for_different_preparation');
      }
      if (['SETTLED', 'REJECTED', 'FAILED_FINAL'].includes(claim.record.state)) return claim.record.result;
      throw new Error(`execution_exists_${claim.record.state.toLowerCase()}_use_reconcile`);
    }

    let hold;
    try {
      hold = this._hold({ request, key: idempotencyKey });
      this.executions.transition({
        key: idempotencyKey,
        request,
        to: 'HELD',
        result: {
          hold_transaction_id: hold.transaction_id,
          hold_record_sha256: hold.record_sha256,
        },
      });
    } catch (err) {
      this.executions.transition({
        key: idempotencyKey,
        request,
        to: 'FAILED_FINAL',
        result: this._result(request, {
          state: 'FAILED_FINAL',
          error: err.message,
          value_moved: false,
        }),
      });
      throw err;
    }

    this.receipts.append({
      event: 'SOVEREIGN_VALUE_HELD',
      source_account_id: request.source_account_id,
      instruction_sha256: request.instruction_sha256,
      governance_proof_sha256: request.governance_proof_sha256,
      hold_record_sha256: hold.record_sha256,
      amount_minor: request.amount_minor,
      currency: request.currency,
      external_submission_performed: false,
      value_moved: false,
    });

    let submission;
    try {
      submission = await this.settlement.submit({
        message: prepared.iso20022,
        instruction: prepared.instruction,
        idempotencyKey,
      });
      const submittedResult = this._result(request, {
        state: 'SUBMITTED',
        submission_id: submission.submission_id,
        submission_receipt_sha256: submission.receipt_sha256,
        external_receipt_sha256: submission.external_receipt_sha256,
        hold_transaction_id: hold.transaction_id,
        value_moved: false,
      });
      this.executions.transition({ key: idempotencyKey, request, to: 'SUBMITTED', result: submittedResult });
      this.receipts.append({
        event: 'SOVEREIGN_SETTLEMENT_SUBMITTED',
        source_account_id: request.source_account_id,
        instruction_sha256: request.instruction_sha256,
        submission_id: submission.submission_id,
        amount_minor: request.amount_minor,
        currency: request.currency,
        external_receipt_sha256: submission.external_receipt_sha256,
        value_moved: false,
      });
    } catch (err) {
      if (err.definitive_rejection === true) {
        const release = this._release({ request, key: idempotencyKey, reason: 'DEFINITIVE_SUBMISSION_REJECTION' });
        const result = this._result(request, { state: 'REJECTED', error: err.message, release_record_sha256: release.record_sha256, value_moved: false });
        this.executions.transition({ key: idempotencyKey, request, to: 'REJECTED', result });
      } else {
        const result = this._result(request, { state: 'UNKNOWN', error: err.message, hold_transaction_id: hold.transaction_id, value_moved: false });
        this.executions.transition({ key: idempotencyKey, request, to: 'UNKNOWN', result });
      }
      throw err;
    }

    let readback;
    try {
      readback = await this.settlement.readback(submission.submission_id);
    } catch (err) {
      const result = this._result(request, {
        state: 'UNKNOWN', submission_id: submission.submission_id, hold_transaction_id: hold.transaction_id, error: err.message, value_moved: false,
      });
      this.executions.transition({ key: idempotencyKey, request, to: 'UNKNOWN', result });
      throw err;
    }

    return this._applyReadback({ key: idempotencyKey, request, readback, submissionId: submission.submission_id });
  }

  _applyReadback({ key, request, readback, submissionId }) {
    const status = String(readback.status || 'UNKNOWN').toUpperCase();
    if (status === 'SETTLED') {
      const booking = this._bookSettled({ request, key, settlementReference: readback.settlement_reference });
      const result = this._result(request, {
        state: 'SETTLED', submission_id: submissionId, settlement_reference: readback.settlement_reference || null,
        external_receipt_sha256: readback.external_receipt_sha256, settlement_ledger_record_sha256: booking.record_sha256,
        value_moved: true, verified_value_flow: true,
      });
      this.executions.transitionExisting({ key, to: 'SETTLED', result });
      this.receipts.append({
        event: 'SOVEREIGN_SETTLEMENT_VERIFIED',
        source_account_id: request.source_account_id,
        instruction_sha256: request.instruction_sha256,
        submission_id: submissionId,
        amount_minor: request.amount_minor,
        currency: request.currency,
        settlement_ledger_record_sha256: booking.record_sha256,
        external_receipt_sha256: readback.external_receipt_sha256,
        value_moved: true,
      });
      return Object.freeze(result);
    }
    if (status === 'REJECTED') {
      const release = this._release({ request, key, reason: 'SETTLEMENT_REJECTED' });
      const result = this._result(request, { state: 'REJECTED', submission_id: submissionId, external_receipt_sha256: readback.external_receipt_sha256, release_record_sha256: release.record_sha256, value_moved: false });
      this.executions.transitionExisting({ key, to: 'REJECTED', result });
      return Object.freeze(result);
    }
    const next = status === 'UNKNOWN' ? 'UNKNOWN' : 'PENDING_SETTLEMENT';
    const current = this.executions.read(key);
    const result = this._result(request, { state: next, submission_id: submissionId, external_receipt_sha256: readback.external_receipt_sha256, provider_status: status, value_moved: false });
    if (current.state !== next) this.executions.transitionExisting({ key, to: next, result });
    this.receipts.append({
      event: 'SOVEREIGN_SETTLEMENT_PENDING',
      source_account_id: request.source_account_id,
      instruction_sha256: request.instruction_sha256,
      submission_id: submissionId,
      amount_minor: request.amount_minor,
      currency: request.currency,
      provider_status: status,
      value_moved: false,
    });
    return Object.freeze(result);
  }

  async reconcile({ idempotencyKey }) {
    requireSovereignLive(this.env);
    const record = this.executions.read(idempotencyKey);
    if (!record) throw new Error('execution_state_missing');
    if (['SETTLED', 'REJECTED', 'FAILED_FINAL'].includes(record.state)) return record.result;
    const submissionId = record.result?.submission_id;
    if (!submissionId) throw new Error('reconciliation_requires_submission_id_manual_investigation');
    const readback = await this.settlement.readback(submissionId);
    return this._applyReadback({ key: idempotencyKey, request: record.request, readback, submissionId });
  }
}

module.exports = { GBankSovereignCore, requireSovereignLive, verifyPrepared };
