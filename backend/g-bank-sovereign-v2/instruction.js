'use strict';

const { canonicalJson, sha256 } = require('./canonical');
const { assertAccountId, assertCurrency, assertMinor } = require('./ledger');
const { normalizeIban, isValidIban } = require('./accounts');

function text(name, value, min = 1, max = 140) {
  const v = String(value || '').trim();
  if (v.length < min || v.length > max) throw new Error(`${name}_invalid`);
  return v;
}

function id35(name, value) {
  const v = text(name, value, 1, 35);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/+-]*$/.test(v)) throw new Error(`${name}_invalid`);
  return v;
}

function bic(value) {
  const v = String(value || '').toUpperCase();
  if (!/^[A-Z0-9]{8}([A-Z0-9]{3})?$/.test(v)) throw new Error('creditor_agent_bic_invalid');
  return v;
}

function normalizeParty(name, party) {
  if (!party || typeof party !== 'object') throw new Error(`${name}_required`);
  const out = { name: text(`${name}_name`, party.name) };
  if (party.address) {
    const country = String(party.address.country || '').toUpperCase();
    const town = text(`${name}_town`, party.address.town);
    if (!/^[A-Z]{2}$/.test(country)) throw new Error(`${name}_country_invalid`);
    out.address = {
      country,
      town,
      street: party.address.street ? text(`${name}_street`, party.address.street, 1, 70) : null,
      building_number: party.address.building_number ? text(`${name}_building_number`, party.address.building_number, 1, 16) : null,
      post_code: party.address.post_code ? text(`${name}_post_code`, party.address.post_code, 1, 16) : null,
    };
  }
  return out;
}

function validIban(name, value) {
  const v = normalizeIban(value);
  if (!isValidIban(v)) throw new Error(`${name}_invalid`);
  return v;
}

function normalizeInstruction(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('settlement_instruction_invalid');
  const amount = assertMinor(input.amount_minor);
  const currency = assertCurrency(input.currency || 'EUR');
  if (currency !== 'EUR') throw new Error('sepa_currency_must_be_eur');
  const scheme = String(input.scheme || 'SCT_INST').toUpperCase();
  if (!['SCT', 'SCT_INST'].includes(scheme)) throw new Error('settlement_scheme_invalid');

  const creditor = normalizeParty('creditor', input.creditor);
  const debtor = normalizeParty('debtor', input.debtor);
  const normalized = {
    schema: 'g-bank-sovereign-payment-instruction/v2',
    instruction_id: id35('instruction_id', input.instruction_id),
    message_id: id35('message_id', input.message_id),
    end_to_end_id: id35('end_to_end_id', input.end_to_end_id),
    source_account_id: assertAccountId(input.source_account_id),
    amount_minor: amount,
    currency,
    scheme,
    debtor,
    debtor_iban: validIban('debtor_iban', input.debtor_iban),
    debtor_agent_bic: input.debtor_agent_bic ? bic(input.debtor_agent_bic) : null,
    creditor,
    creditor_iban: validIban('creditor_iban', input.creditor_iban),
    creditor_agent_bic: bic(input.creditor_agent_bic),
    remittance: input.remittance ? text('remittance', input.remittance, 1, 140) : '',
    requested_at: input.requested_at || new Date().toISOString(),
  };
  normalized.beneficiary_binding_sha256 = sha256(canonicalJson({
    creditor: normalized.creditor,
    creditor_iban: normalized.creditor_iban,
    creditor_agent_bic: normalized.creditor_agent_bic,
  }));
  normalized.instruction_sha256 = sha256(canonicalJson(normalized));
  return Object.freeze(normalized);
}

module.exports = { normalizeInstruction, id35, bic };
