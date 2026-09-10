'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function hash64(name, value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}_invalid`);
  return hash;
}

function requireInboundRecord(record) {
  if (!record || record.schema !== 'g-bank-inbound-state-record/v2') throw new Error('inbound_record_required');
  if (!['PENDING', 'AVAILABLE'].includes(record.state)) throw new Error('inbound_exception_state_invalid');
  hash64('inbound_event_sha256', record.event_sha256);
  return record;
}

function createReturnRequest({ inboundRecord, reason_code, operator_evidence_sha256, now = Date.now() }) {
  const inbound = requireInboundRecord(inboundRecord);
  const reason = String(reason_code || '').toUpperCase();
  if (!/^[A-Z0-9]{2,8}$/.test(reason)) throw new Error('return_reason_code_invalid');
  const body = {
    schema: 'g-bank-inbound-return-request/v2',
    state: 'REQUESTED_NOT_SUBMITTED',
    inbound_id: inbound.inbound_id,
    inbound_event_sha256: inbound.event_sha256,
    target_account_id: inbound.target_account_id,
    amount_minor: inbound.amount_minor,
    currency: inbound.currency,
    reason_code: reason,
    operator_evidence_sha256: hash64('return_operator_evidence_sha256', operator_evidence_sha256),
    requested_at: new Date(now).toISOString(),
    external_submission_performed: false,
    value_moved: false,
  };
  return Object.freeze({ ...body, request_sha256: sha256(canonicalJson(body)) });
}

function createRecallDecision({ inboundRecord, decision, operator_evidence_sha256, reason = null, now = Date.now() }) {
  const inbound = requireInboundRecord(inboundRecord);
  const normalized = String(decision || '').toUpperCase();
  if (!['ACCEPT_FOR_REVIEW', 'REJECT'].includes(normalized)) throw new Error('recall_decision_invalid');
  const body = {
    schema: 'g-bank-inbound-recall-decision/v2',
    state: 'DECIDED_NOT_SUBMITTED',
    decision: normalized,
    inbound_id: inbound.inbound_id,
    inbound_event_sha256: inbound.event_sha256,
    target_account_id: inbound.target_account_id,
    amount_minor: inbound.amount_minor,
    currency: inbound.currency,
    operator_evidence_sha256: hash64('recall_operator_evidence_sha256', operator_evidence_sha256),
    reason: reason ? String(reason).slice(0, 256) : null,
    decided_at: new Date(now).toISOString(),
    external_submission_performed: false,
    value_moved: false,
  };
  return Object.freeze({ ...body, decision_sha256: sha256(canonicalJson(body)) });
}

module.exports = { createReturnRequest, createRecallDecision };
