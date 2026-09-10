'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { assertCurrency, assertMinor } = require('./ledger');
const { isValidIban, normalizeIban } = require('./accounts');

function verifyHashBound(name, value, hashField) {
  if (!value || typeof value !== 'object') throw new Error(`${name}_required`);
  const supplied = String(value[hashField] || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) throw new Error(`${name}_hash_invalid`);
  const { [hashField]: omitted, ...body } = value;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error(`${name}_hash_mismatch`);
  return value;
}

function verifyInboundSettlementEvidence(event, { now = Date.now(), max_age_ms = 7 * 24 * 60 * 60 * 1000 } = {}) {
  verifyHashBound('inbound_event', event, 'event_sha256');
  if (event.schema !== 'g-bank-inbound-settlement-evidence/v2') throw new Error('inbound_event_schema_invalid');
  if (!['VERIFIED_EXTERNAL_READBACK', 'VERIFIED_EXTERNAL_STATEMENT'].includes(event.source)) throw new Error('inbound_event_source_invalid');
  if (String(event.status || '').toUpperCase() !== 'SETTLED') throw new Error('inbound_event_not_settled');
  const scheme = String(event.scheme || '').toUpperCase();
  if (!['SCT', 'SCT_INST'].includes(scheme)) throw new Error('inbound_scheme_invalid');
  const inboundId = String(event.inbound_id || '').trim();
  if (!inboundId || inboundId.length > 256) throw new Error('inbound_id_invalid');
  const amount = assertMinor(event.amount_minor);
  const currency = assertCurrency(event.currency);
  const iban = normalizeIban(event.creditor_iban);
  if (!isValidIban(iban)) throw new Error('inbound_creditor_iban_invalid');
  const observed = Date.parse(event.observed_at);
  if (!Number.isFinite(observed) || observed > now + 30000 || now - observed > max_age_ms) throw new Error('inbound_event_stale');
  const settlementSystem = String(event.settlement_system || '').trim();
  if (!settlementSystem || settlementSystem.length > 128) throw new Error('inbound_settlement_system_invalid');
  const externalReceipt = String(event.external_receipt_sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(externalReceipt)) throw new Error('inbound_external_receipt_sha256_invalid');
  return Object.freeze({ inbound_id: inboundId, amount_minor: amount, currency, creditor_iban: iban, scheme, event_sha256: event.event_sha256 });
}

function verifyReleaseEvidence(evidence, current, { now = Date.now(), max_age_ms = 15 * 60 * 1000 } = {}) {
  verifyHashBound('inbound_release_evidence', evidence, 'release_sha256');
  if (evidence.schema !== 'g-bank-inbound-release-evidence/v2' || evidence.state !== 'PASS') throw new Error('inbound_release_evidence_invalid');
  if (evidence.inbound_id !== current.inbound_id) throw new Error('inbound_release_id_mismatch');
  if (evidence.inbound_event_sha256 !== current.event_sha256) throw new Error('inbound_release_event_mismatch');
  if (evidence.target_account_id !== current.target_account_id) throw new Error('inbound_release_account_mismatch');
  if (Number(evidence.amount_minor) !== current.amount_minor) throw new Error('inbound_release_amount_mismatch');
  if (String(evidence.currency || '').toUpperCase() !== current.currency) throw new Error('inbound_release_currency_mismatch');
  const verified = Date.parse(evidence.verified_at);
  if (!Number.isFinite(verified) || verified > now + 30000 || now - verified > max_age_ms) throw new Error('inbound_release_evidence_stale');
  return true;
}

function ledgerTransaction(ledger, transactionId) {
  return ledger.records().find(record => record.transaction_id === transactionId) || null;
}

function verifyPendingBooking(record, event, { settlementAccountId, suspenseAccountId, targetAccountId }) {
  if (!record) return false;
  if (record.metadata?.inbound_event_sha256 !== event.event_sha256) throw new Error('inbound_pending_recovery_event_mismatch');
  if (record.metadata?.target_account_id !== targetAccountId) throw new Error('inbound_pending_recovery_account_mismatch');
  const expected = [
    `${settlementAccountId}|DEBIT|${event.amount_minor}|${event.currency}`,
    `${suspenseAccountId}|CREDIT|${event.amount_minor}|${event.currency}`,
  ].sort();
  const actual = (record.entries || []).map(entry => `${entry.account_id}|${entry.side}|${entry.amount_minor}|${entry.currency}`).sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error('inbound_pending_recovery_entries_mismatch');
  return true;
}

function verifyAvailableBooking(record, current, { suspenseAccountId, targetAccountId }) {
  if (!record) return false;
  if (record.metadata?.inbound_event_sha256 !== current.event_sha256) throw new Error('inbound_available_recovery_event_mismatch');
  const expected = [
    `${suspenseAccountId}|DEBIT|${current.amount_minor}|${current.currency}`,
    `${targetAccountId}|CREDIT|${current.amount_minor}|${current.currency}`,
  ].sort();
  const actual = (record.entries || []).map(entry => `${entry.account_id}|${entry.side}|${entry.amount_minor}|${entry.currency}`).sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error('inbound_available_recovery_entries_mismatch');
  return true;
}

class InboundPaymentProcessor {
  constructor({ accounts, ledger, inboundStore, settlement_account_id, inbound_suspense_account_id }) {
    if (!accounts || typeof accounts.findByIban !== 'function') throw new Error('account_registry_required');
    if (!ledger || typeof ledger.post !== 'function' || typeof ledger.records !== 'function') throw new Error('sovereign_ledger_required');
    if (!inboundStore || typeof inboundStore.claim !== 'function') throw new Error('inbound_store_required');
    this.accounts = accounts;
    this.ledger = ledger;
    this.store = inboundStore;
    this.settlementAccountId = String(settlement_account_id || '');
    this.suspenseAccountId = String(inbound_suspense_account_id || '');
  }

  ingest(event, { now = Date.now() } = {}) {
    const verified = verifyInboundSettlementEvidence(event, { now });
    const customer = this.accounts.findByIban(verified.creditor_iban);
    if (customer.type !== 'CUSTOMER' || customer.status !== 'ACTIVE') throw new Error('inbound_target_customer_not_active');
    if (customer.currency !== verified.currency) throw new Error('inbound_target_currency_mismatch');
    const settlement = this.accounts.requireActive(this.settlementAccountId, verified.currency);
    const suspense = this.accounts.requireActive(this.suspenseAccountId, verified.currency);
    if (settlement.type !== 'SETTLEMENT') throw new Error('inbound_settlement_account_type_invalid');
    if (suspense.type !== 'SUSPENSE') throw new Error('inbound_suspense_account_type_invalid');

    const claim = this.store.claim({
      inbound_id: verified.inbound_id,
      event_sha256: verified.event_sha256,
      target_account_id: customer.account_id,
      amount_minor: verified.amount_minor,
      currency: verified.currency,
      now,
    });
    if (!claim.owner && claim.record.state !== 'CLAIMED') return claim.record;

    const transactionId = `INBOUND:PENDING:${sha256(`${verified.inbound_id}:${verified.event_sha256}`).slice(0, 32)}`;
    let booking = ledgerTransaction(this.ledger, transactionId);
    if (booking) {
      verifyPendingBooking(booking, verified, {
        settlementAccountId: this.settlementAccountId,
        suspenseAccountId: this.suspenseAccountId,
        targetAccountId: customer.account_id,
      });
    } else {
      booking = this.ledger.post({
        transaction_id: transactionId,
        reference: verified.inbound_id,
        entries: [
          { account_id: this.settlementAccountId, side: 'DEBIT', amount_minor: verified.amount_minor, currency: verified.currency },
          { account_id: this.suspenseAccountId, side: 'CREDIT', amount_minor: verified.amount_minor, currency: verified.currency },
        ],
        metadata: {
          kind: 'INBOUND_SETTLEMENT_PENDING',
          inbound_id: verified.inbound_id,
          inbound_event_sha256: verified.event_sha256,
          target_account_id: customer.account_id,
        },
      });
    }
    return this.store.transition({
      inbound_id: verified.inbound_id,
      expected_state: 'CLAIMED',
      to_state: 'PENDING',
      evidence_sha256: verified.event_sha256,
      ledger_record_sha256: booking.record_sha256,
      now,
    });
  }

  makeAvailable({ inbound_id, releaseEvidence, now = Date.now() }) {
    const current = this.store.current(inbound_id);
    if (!current) throw new Error('inbound_state_missing');
    if (current.state === 'AVAILABLE') return current;
    if (current.state !== 'PENDING') throw new Error('inbound_not_pending');
    verifyReleaseEvidence(releaseEvidence, current, { now });
    const customer = this.accounts.requireActive(current.target_account_id, current.currency);
    if (customer.type !== 'CUSTOMER') throw new Error('inbound_target_customer_invalid');
    const suspense = this.accounts.requireActive(this.suspenseAccountId, current.currency);
    if (suspense.type !== 'SUSPENSE') throw new Error('inbound_suspense_account_type_invalid');

    const transactionId = `INBOUND:AVAILABLE:${sha256(`${current.inbound_id}:${current.event_sha256}`).slice(0, 32)}`;
    let booking = ledgerTransaction(this.ledger, transactionId);
    if (booking) {
      verifyAvailableBooking(booking, current, { suspenseAccountId: this.suspenseAccountId, targetAccountId: customer.account_id });
    } else {
      booking = this.ledger.post({
        transaction_id: transactionId,
        reference: current.inbound_id,
        entries: [
          { account_id: this.suspenseAccountId, side: 'DEBIT', amount_minor: current.amount_minor, currency: current.currency },
          { account_id: customer.account_id, side: 'CREDIT', amount_minor: current.amount_minor, currency: current.currency },
        ],
        metadata: {
          kind: 'INBOUND_SETTLEMENT_AVAILABLE',
          inbound_id: current.inbound_id,
          inbound_event_sha256: current.event_sha256,
          release_sha256: releaseEvidence.release_sha256,
          target_account_id: customer.account_id,
        },
      });
    }
    return this.store.transition({
      inbound_id: current.inbound_id,
      expected_state: 'PENDING',
      to_state: 'AVAILABLE',
      evidence_sha256: releaseEvidence.release_sha256,
      ledger_record_sha256: booking.record_sha256,
      now,
    });
  }
}

module.exports = {
  InboundPaymentProcessor,
  verifyInboundSettlementEvidence,
  verifyReleaseEvidence,
};
