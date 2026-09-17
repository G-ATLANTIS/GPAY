#!/usr/bin/env node
'use strict';

const { HIGH_VALUE_EUR_MINOR } = require('./atlas-payment-v2-policy');

function required(value, field, max = 256) {
  const text = String(value ?? '').trim();
  if (!text) throw new Error(`${field}_required`);
  if (text.length > max || /[\r\n]/.test(text)) {
    throw new Error(`${field}_invalid`);
  }
  return text;
}

function normalizeIban(value) {
  const iban = String(value ?? '').replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(iban)) {
    throw new Error('beneficiary_iban_invalid');
  }
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const fragment = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of fragment) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  if (remainder !== 1) throw new Error('beneficiary_iban_checksum_invalid');
  return iban;
}
function validateReturnUri(value) {
  const uri = required(value, 'return_uri', 2048);
  const parsed = new URL(uri);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw new Error('return_uri_invalid');
  }
  return uri;
}

function buildProviderSelection({ amount_in_minor, provider_id, country_code = 'NL' }) {
  const highValue = amount_in_minor >= HIGH_VALUE_EUR_MINOR;
  if (highValue) {
    const providerId = required(provider_id, 'provider_id', 200);
    return {
      type: 'preselected',
      provider_id: providerId,
      scheme_selection: {
        type: 'preselected',
        scheme_id: 'sepa_credit_transfer'
      }
    };
  }
  return {
    type: 'user_selected',
    filter: {
      countries: [required(country_code, 'country_code', 2).toUpperCase()],
      customer_segments: ['retail']
    },
    scheme_selection: { type: 'instant_preferred', allow_remitter_fee: false }
  };
}
function buildPaymentPayload(input = {}) {
  const amount = Number(input.amount_in_minor);
  if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('amount_invalid');
  if (String(input.currency).toUpperCase() !== 'EUR') throw new Error('currency_invalid');

  const name = required(input.beneficiary_name, 'beneficiary_name', 160);
  const iban = normalizeIban(input.beneficiary_iban);
  const reference = required(input.reference, 'reference', 18);
  const userName = required(input.user_name, 'user_name', 180);
  const email = String(input.user_email || '').trim();
  const phone = String(input.user_phone || '').trim();
  if (!email && !phone) throw new Error('user_contact_required');

  const user = { name: userName };
  if (email) user.email = email;
  if (phone) user.phone = phone;

  return {
    amount_in_minor: amount,
    currency: 'EUR',
    payment_method: {
      type: 'bank_transfer',
      provider_selection: buildProviderSelection(input),
      beneficiary: {
        type: 'external_account',
        account_holder_name: name,
        account_identifier: { type: 'iban', iban },
        reference
      }
    },    hosted_page: {
      country_code: required(input.country_code || 'NL', 'country_code', 2).toUpperCase(),
      language_code: required(input.language_code || 'nl', 'language_code', 2).toLowerCase(),
      return_uri: validateReturnUri(input.return_uri),
      max_wait_for_result: 10
    },
    user,
    metadata: {
      atlas_payment_fabric: 'v2',
      atlas_intent_id: required(input.intent_id, 'intent_id', 64)
    }
  };
}

module.exports = {
  normalizeIban,
  validateReturnUri,
  buildProviderSelection,
  buildPaymentPayload
};
