'use strict';

const path = require('node:path');
const { IdempotencyStore } = require('../g-bank-live-v1/idempotency-store');
const { ReceiptLedger } = require('../g-bank-live-v1/receipt-ledger');
const { sha256 } = require('../g-bank-live-v1/canonical');
const { RESULT_STATE, CANONICAL_COMMIT_STATUS } = require('./states');

// G-BANK-CANONICAL-LIVE-ROUTING-P0 — one authoritative answer.
//
// Whether a payment "happened" is answered ONLY from spine state:
//   * the idempotency record (was it claimed / finalized, in what terminal
//     state, with what committed result), and
//   * the hash-chained audit ledger (EXECUTION_AUTHORIZED / VERIFIED_EXECUTION_
//     COMMIT / *_UNCONFIRMED / RECONCILED_* rows for this idempotency key).
//
// Legacy G_*.json evidence files and the old openbanking receipt system are
// NOT consulted and never determine canonical success.

function getExecutionTruth(idempotencyKey, context = {}) {
  const stateDir = path.resolve(context.stateDir || '.secrets/g-verified-execution-spine');
  const idempotency =
    context.idempotency || new IdempotencyStore(path.join(stateDir, 'idempotency'));
  const ledger = context.ledger || new ReceiptLedger(path.join(stateDir, 'audit.jsonl'));

  const keyHash = sha256(String(idempotencyKey));
  const record = idempotency.read(idempotencyKey);

  let ledgerValid = null;
  let rows = [];
  try {
    ledgerValid = ledger.verify().valid;
    rows = ledger.readAll().filter(
      (r) => r.idempotency_key_sha256 === keyHash || (record && r.execution_id && record.result && r.execution_id === record.result.execution_id),
    );
  } catch (err) {
    ledgerValid = false;
  }

  const committedResult =
    record && record.state === 'SUCCEEDED' && record.result && record.result.state === RESULT_STATE.VERIFIED_SUCCESS
      ? record.result
      : null;

  const authorized =
    !!record || rows.some((r) => r.event === 'EXECUTION_AUTHORIZED');
  const executionAttempted =
    rows.some((r) => ['EXECUTION_AUTHORIZED', 'VERIFIED_EXECUTION_COMMIT', 'EXECUTION_UNCONFIRMED', 'EXECUTION_PROVIDER_FAILURE', 'EXECUTION_READBACK_MISMATCH', 'EXECUTION_READBACK_UNCERTAIN'].includes(r.event)) ||
    (record && record.state !== 'PENDING');
  const providerAccepted =
    !!committedResult ||
    (record && record.state === 'UNKNOWN_REQUIRES_RECONCILIATION' && record.result && record.result.provider_request_id != null) ||
    rows.some((r) => r.event === 'RECONCILED_EFFECT_CONFIRMED');
  const externallyVerified =
    !!committedResult &&
    committedResult.verification_method === 'AUTHENTICATED_PROVIDER_READBACK' &&
    committedResult.assurance_level_achieved === 'L4';
  const canonical =
    !!committedResult && committedResult.canonical_commit_status === CANONICAL_COMMIT_STATUS.COMMITTED && ledgerValid === true;

  // Retry is safe ONLY when there is no record, or reconcile proved the effect
  // absent, or a definite provider failure with no external effect.
  let retrySafe = false;
  let retryReason;
  if (!record) {
    retrySafe = true;
    retryReason = 'no prior record';
  } else if (record.state === 'FAILED_FINAL') {
    retrySafe = true;
    retryReason = 'provider returned a definite failure; no external effect';
  } else if (rows.some((r) => r.event === 'RECONCILED_EFFECT_ABSENT')) {
    retrySafe = true;
    retryReason = 'reconcile proved the external effect absent';
  } else if (record.state === 'SUCCEEDED') {
    retrySafe = false;
    retryReason = 'already committed; a retry would return the recorded result, not re-execute';
  } else {
    retrySafe = false;
    retryReason = `record in ${record.state}; reconcile must resolve before any retry`;
  }

  return {
    idempotency_key_sha256: keyHash,
    record_state: record ? record.state : null,
    audit_chain_valid: ledgerValid,
    authorized,
    execution_attempted: executionAttempted,
    provider_accepted: providerAccepted,
    externally_verified: externallyVerified,
    canonical,
    canonical_success: canonical,
    retry_safe: retrySafe,
    retry_reason: retryReason,
    committed_result_sha256: committedResult ? committedResult.result_sha256 : null,
    audit_events: rows.map((r) => ({ sequence: r.sequence, event: r.event })),
  };
}

module.exports = { getExecutionTruth };
