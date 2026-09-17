#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const { OpenBankingAdapter, sha256 } = require('./atlas-open-banking-core');

function bool(value) { return String(value || '').toLowerCase() === 'true'; }
function set(value) { return typeof value === 'string' && value.trim().length > 0; }
function idempotencyKey(intent) {
  return crypto.createHash('sha256').update(`atlas:${intent.intent_binding_sha256}`).digest('hex');
}

class YapilyConnectAdapter extends OpenBankingAdapter {
  constructor({ env = process.env } = {}) {
    super({ id: 'yapily-connect', type: 'SPONSORED_PISP', priority: 30 });
    this.env = env;
  }
  capabilitySnapshot({ intent }) {
    const max = Number(this.env.YAPILY_APPROVED_MAX_PAYMENT_EUR || 0);
    const authenticated = set(this.env.YAPILY_APPLICATION_KEY) && set(this.env.YAPILY_APPLICATION_SECRET);
    const sponsorApproved = bool(this.env.YAPILY_CONNECT_APPROVED);
    const highValueApproved = bool(this.env.YAPILY_HIGH_VALUE_WAIVER_APPROVED);
    const blockers = [];
    if (!sponsorApproved) blockers.push('SPONSOR_ONBOARDING_NOT_APPROVED');
    if (!highValueApproved && intent.amount_in_minor > 1_500_000) blockers.push('HIGH_VALUE_WAIVER_NOT_APPROVED');
    return {
      environment: this.env.YAPILY_ENV === 'production' ? 'PRODUCTION' : 'SANDBOX',
      authenticated,
      execution_authorized: sponsorApproved && highValueApproved,
      currency: 'EUR',
      max_amount_in_minor: Number.isFinite(max) ? Math.round(max * 100) : 0,
      blockers
    };
  }
  buildInitiationRequest({ intent, institution_id, raw_beneficiary_iban, callback_url }) {
    if (!institution_id) throw new Error('institution_id_required');
    if (!raw_beneficiary_iban) throw new Error('beneficiary_iban_required');
    if (!/^https:\/\//.test(String(callback_url || ''))) throw new Error('callback_https_required');
    return {
      schema: 'atlas-yapily-connect-request-v1',
      provider: 'yapily',
      institution_id: String(institution_id),
      idempotency_key: idempotencyKey(intent),
      payment_request: {
        type: 'DOMESTIC_PAYMENT',
        amount: { amount: (intent.amount_in_minor / 100).toFixed(2), currency: 'EUR' },
        payee: { account_identifications: [{ type: 'IBAN', identification: String(raw_beneficiary_iban) }] },
        reference: intent.reference,
        callback_url: String(callback_url)
      },
      intent_binding_sha256: intent.intent_binding_sha256,
      network_request_performed: false,
      value_moved: false
    };
  }
  normalizeStatus(resource = {}) {
    const raw = String(resource.status || '').toUpperCase();
    const map = { PENDING: 'PENDING', AUTHORIZED: 'AUTHORIZED', EXECUTED: 'PROVIDER_EXECUTED', COMPLETED: 'PROVIDER_EXECUTED', FAILED: 'FAILED' };
    return map[raw] || 'UNKNOWN';
  }
}

class BunqNativeAdapter extends OpenBankingAdapter {
  constructor({ env = process.env } = {}) {
    super({ id: 'bunq-native-draft', type: 'BANK_NATIVE', priority: 10 });
    this.env = env;
  }
  capabilitySnapshot({ intent }) {
    const max = Number(this.env.BUNQ_VERIFIED_MAX_PAYMENT_EUR || 0);
    const authenticated = set(this.env.BUNQ_API_KEY) && this.env.BUNQ_ENV === 'production';
    const limitVerified = bool(this.env.BUNQ_LIMIT_EVIDENCE_VERIFIED);
    const blockers = [];
    if (!limitVerified) blockers.push('BANK_LIMIT_EVIDENCE_REQUIRED');
    if (!bool(this.env.BUNQ_DRAFT_PAYMENT_WRITE_VERIFIED)) blockers.push('DRAFT_PAYMENT_WRITE_NOT_VERIFIED');
    return {
      environment: this.env.BUNQ_ENV === 'production' ? 'PRODUCTION' : 'SANDBOX',
      authenticated,
      execution_authorized: authenticated && limitVerified && bool(this.env.BUNQ_DRAFT_PAYMENT_WRITE_VERIFIED),
      currency: 'EUR',
      max_amount_in_minor: Number.isFinite(max) ? Math.round(max * 100) : 0,
      blockers
    };
  }
  buildInitiationRequest({ intent, user_id, monetary_account_id, raw_beneficiary_iban }) {
    if (!user_id || !monetary_account_id) throw new Error('bunq_account_binding_required');
    if (!raw_beneficiary_iban) throw new Error('beneficiary_iban_required');
    return {
      schema: 'atlas-bunq-draft-payment-request-v1',
      provider: 'bunq',
      method: 'POST',
      path: `/v1/user/${encodeURIComponent(user_id)}/monetary-account/${encodeURIComponent(monetary_account_id)}/draft-payment`,
      idempotency_key: idempotencyKey(intent),
      payload: {
        amount: { value: (intent.amount_in_minor / 100).toFixed(2), currency: 'EUR' },
        counterparty_alias: { type: 'IBAN', value: String(raw_beneficiary_iban), name: intent.beneficiary_name },
        description: intent.reference
      },
      requires_user_bank_approval: true,
      intent_binding_sha256: intent.intent_binding_sha256,
      network_request_performed: false,
      value_moved: false
    };
  }
  normalizeStatus(resource = {}) {
    const raw = String(resource.status || '').toUpperCase();
    const map = { PENDING: 'PENDING_APPROVAL', ACCEPTED: 'AUTHORIZED', COMPLETED: 'PROVIDER_EXECUTED', FAILED: 'FAILED', REJECTED: 'FAILED' };
    return map[raw] || 'UNKNOWN';
  }
}

module.exports = {
  YapilyConnectAdapter,
  BunqNativeAdapter,
  idempotencyKey
};

class OwnPispAdapter extends OpenBankingAdapter {
  constructor({ env = process.env } = {}) {
    super({ id: 'atlas-own-pisp', type: 'OWN_PISP', priority: 20 });
    this.env = env;
  }
  capabilitySnapshot({ intent }) {
    const max = Number(this.env.ATLAS_PISP_VERIFIED_MAX_PAYMENT_EUR || 0);
    const authenticated = bool(this.env.ATLAS_PISP_DNB_AUTHORISED) && bool(this.env.ATLAS_PISP_EIDAS_READY);
    const registrationReady = bool(this.env.ATLAS_PISP_BANK_REGISTRATION_VERIFIED);
    const blockers = [];
    if (!bool(this.env.ATLAS_PISP_DNB_AUTHORISED)) blockers.push('DNB_AUTHORISATION_REQUIRED');
    if (!bool(this.env.ATLAS_PISP_EIDAS_READY)) blockers.push('EIDAS_IDENTITY_REQUIRED');
    if (!registrationReady) blockers.push('BANK_REGISTRATION_REQUIRED');
    return {
      environment: bool(this.env.ATLAS_PISP_PRODUCTION) ? 'PRODUCTION' : 'SANDBOX',
      authenticated,
      execution_authorized: authenticated && registrationReady,
      currency: 'EUR',
      max_amount_in_minor: Number.isFinite(max) ? Math.round(max * 100) : 0,
      blockers
    };
  }
  buildInitiationRequest({ intent, institution_id, raw_beneficiary_iban, callback_url }) {
    if (!institution_id || !raw_beneficiary_iban) throw new Error('own_pisp_routing_data_required');
    if (!/^https:\/\//.test(String(callback_url || ''))) throw new Error('callback_https_required');
    return {
      schema: 'atlas-own-pisp-request-v1', provider: 'atlas-own-pisp',
      institution_id: String(institution_id), idempotency_key: idempotencyKey(intent),
      amount_in_minor: intent.amount_in_minor, currency: intent.currency,
      beneficiary_iban: String(raw_beneficiary_iban), reference: intent.reference,
      callback_url: String(callback_url), intent_binding_sha256: intent.intent_binding_sha256,
      network_request_performed: false, value_moved: false
    };
  }
  normalizeStatus(resource = {}) {
    return String(resource.normalized_status || 'UNKNOWN').toUpperCase();
  }
}
class DirectBankAdapter extends OpenBankingAdapter {
  constructor({ bank_id, env = process.env, priority = 15 } = {}) {
    const bank = String(bank_id || '').trim().toLowerCase();
    if (!bank) throw new Error('bank_id_required');
    super({ id: `direct-bank-${bank}`, type: 'BANK_NATIVE', priority });
    this.bank = bank;
    this.env = env;
  }
  capabilitySnapshot({ intent }) {
    const prefix = `ATLAS_BANK_${this.bank.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_`;
    const max = Number(this.env[`${prefix}VERIFIED_MAX_PAYMENT_EUR`] || 0);
    const auth = bool(this.env[`${prefix}AUTHENTICATED`]);
    const write = bool(this.env[`${prefix}PAYMENT_WRITE_VERIFIED`]);
    const limit = bool(this.env[`${prefix}LIMIT_EVIDENCE_VERIFIED`]);
    const blockers = [];
    if (!auth) blockers.push('BANK_AUTHENTICATION_REQUIRED');
    if (!write) blockers.push('BANK_PAYMENT_WRITE_NOT_VERIFIED');
    if (!limit) blockers.push('BANK_LIMIT_EVIDENCE_REQUIRED');
    return {
      environment: bool(this.env[`${prefix}PRODUCTION`]) ? 'PRODUCTION' : 'SANDBOX',
      authenticated: auth,
      execution_authorized: auth && write && limit,
      currency: 'EUR',
      max_amount_in_minor: Number.isFinite(max) ? Math.round(max * 100) : 0,
      blockers
    };
  }
  buildInitiationRequest({ intent, raw_beneficiary_iban }) {
    if (!raw_beneficiary_iban) throw new Error('beneficiary_iban_required');
    return {
      schema: 'atlas-direct-bank-payment-request-v1', bank_id: this.bank,
      amount_in_minor: intent.amount_in_minor, currency: 'EUR',
      beneficiary_iban: String(raw_beneficiary_iban), beneficiary_name: intent.beneficiary_name,
      reference: intent.reference, idempotency_key: idempotencyKey(intent),
      requires_user_bank_approval: true,
      network_request_performed: false, value_moved: false
    };
  }
  normalizeStatus(resource = {}) { return String(resource.normalized_status || 'UNKNOWN').toUpperCase(); }
}

module.exports.OwnPispAdapter = OwnPispAdapter;
module.exports.DirectBankAdapter = DirectBankAdapter;


class AdyenOutboundAdapter extends OpenBankingAdapter {
  constructor({ env = process.env } = {}) {
    super({ id: 'adyen-api', type: 'OUTBOUND_PROVIDER', priority: 25 });
    this.env = env;
  }
  capabilitySnapshot() {
    const max = Number(this.env.ADYEN_VERIFIED_MAX_PAYMENT_EUR || 0);
    const authenticated = set(this.env.ADYEN_API_KEY) && set(this.env.ADYEN_MERCHANT_ACCOUNT) && this.env.ADYEN_ENV === 'production';
    const entitlement = bool(this.env.ADYEN_OUTBOUND_PAYMENTS_APPROVED);
    const limit = bool(this.env.ADYEN_LIMIT_EVIDENCE_VERIFIED);
    const callback = bool(this.env.ADYEN_CALLBACK_VERIFIED);
    const readback = bool(this.env.ADYEN_READBACK_VERIFIED);
    const blockers = [];
    if (!entitlement) blockers.push('OUTBOUND_ENTITLEMENT_REQUIRED');
    if (!limit) blockers.push('PROVIDER_LIMIT_EVIDENCE_REQUIRED');
    if (!callback) blockers.push('CALLBACK_VERIFICATION_REQUIRED');
    if (!readback) blockers.push('READBACK_VERIFICATION_REQUIRED');
    return {
      environment: this.env.ADYEN_ENV === 'production' ? 'PRODUCTION' : 'SANDBOX',
      authenticated,
      execution_authorized: authenticated && entitlement && limit && callback && readback,
      currency: 'EUR',
      max_amount_in_minor: Number.isFinite(max) ? Math.round(max * 100) : 0,
      blockers
    };
  }
  buildInitiationRequest({ intent, raw_beneficiary_iban }) {
    if (!raw_beneficiary_iban) throw new Error('beneficiary_iban_required');
    if (!set(this.env.ADYEN_MERCHANT_ACCOUNT)) throw new Error('adyen_merchant_account_required');
    return {
      schema: 'atlas-adyen-outbound-request-v1', provider: 'adyen',
      merchant_account: this.env.ADYEN_MERCHANT_ACCOUNT,
      amount_in_minor: intent.amount_in_minor, currency: 'EUR',
      beneficiary_iban: String(raw_beneficiary_iban), beneficiary_name: intent.beneficiary_name,
      reference: intent.reference, idempotency_key: idempotencyKey(intent),
      intent_binding_sha256: intent.intent_binding_sha256,
      network_request_performed: false, value_moved: false
    };
  }
  normalizeStatus(resource = {}) { return String(resource.normalized_status || resource.status || 'UNKNOWN').toUpperCase(); }
}

class TinkOpenBankingAdapter extends OpenBankingAdapter {
  constructor({ env = process.env } = {}) {
    super({ id: 'tink-open-banking', type: 'SPONSORED_PISP', priority: 35 });
    this.env = env;
  }
  capabilitySnapshot() {
    const max = Number(this.env.TINK_VERIFIED_MAX_PAYMENT_EUR || 0);
    const authenticated = set(this.env.TINK_CLIENT_ID) && set(this.env.TINK_CLIENT_SECRET) && this.env.TINK_ENV === 'production';
    const onboarding = bool(this.env.TINK_PRODUCTION_ONBOARDING_VERIFIED);
    const pisp = bool(this.env.TINK_PISP_VERIFIED);
    const limit = bool(this.env.TINK_LIMIT_EVIDENCE_VERIFIED);
    const callback = bool(this.env.TINK_CALLBACK_VERIFIED);
    const readback = bool(this.env.TINK_READBACK_VERIFIED);
    const blockers = [];
    if (!onboarding) blockers.push('PRODUCTION_ONBOARDING_REQUIRED');
    if (!pisp) blockers.push('PISP_ENTITLEMENT_REQUIRED');
    if (!limit) blockers.push('PROVIDER_LIMIT_EVIDENCE_REQUIRED');
    if (!callback) blockers.push('CALLBACK_VERIFICATION_REQUIRED');
    if (!readback) blockers.push('READBACK_VERIFICATION_REQUIRED');
    return {
      environment: this.env.TINK_ENV === 'production' ? 'PRODUCTION' : 'SANDBOX',
      authenticated,
      execution_authorized: authenticated && onboarding && pisp && limit && callback && readback,
      currency: 'EUR',
      max_amount_in_minor: Number.isFinite(max) ? Math.round(max * 100) : 0,
      blockers
    };
  }
  buildInitiationRequest({ intent, institution_id, raw_beneficiary_iban, callback_url }) {
    if (!institution_id) throw new Error('institution_id_required');
    if (!raw_beneficiary_iban) throw new Error('beneficiary_iban_required');
    if (!/^https:\/\//.test(String(callback_url || ''))) throw new Error('callback_https_required');
    return {
      schema: 'atlas-tink-payment-request-v1', provider: 'tink', institution_id: String(institution_id),
      amount_in_minor: intent.amount_in_minor, currency: 'EUR',
      beneficiary_iban: String(raw_beneficiary_iban), beneficiary_name: intent.beneficiary_name,
      reference: intent.reference, callback_url: String(callback_url),
      idempotency_key: idempotencyKey(intent), intent_binding_sha256: intent.intent_binding_sha256,
      network_request_performed: false, value_moved: false
    };
  }
  normalizeStatus(resource = {}) { return String(resource.normalized_status || resource.status || 'UNKNOWN').toUpperCase(); }
}

class DirectSepaAdapter extends OpenBankingAdapter {
  constructor({ env = process.env } = {}) {
    super({ id: 'atlas-direct-sepa', type: 'DIRECT_SEPA', priority: 18 });
    this.env = env;
  }
  capabilitySnapshot() {
    const max = Number(this.env.ATLAS_DIRECT_SEPA_VERIFIED_MAX_PAYMENT_EUR || 0);
    const psp = bool(this.env.ATLAS_DIRECT_SEPA_PSP_AUTHORIZATION_VERIFIED);
    const network = bool(this.env.ATLAS_DIRECT_SEPA_NETWORK_ACCESS_VERIFIED);
    const settlement = bool(this.env.ATLAS_DIRECT_SEPA_SETTLEMENT_ACCESS_VERIFIED);
    const sca = bool(this.env.ATLAS_DIRECT_SEPA_SCA_VERIFIED);
    const limit = bool(this.env.ATLAS_DIRECT_SEPA_LIMIT_EVIDENCE_VERIFIED);
    const blockers = [];
    if (!psp) blockers.push('PSP_AUTHORIZATION_REQUIRED');
    if (!network) blockers.push('SEPA_NETWORK_ACCESS_REQUIRED');
    if (!settlement) blockers.push('SETTLEMENT_ACCESS_REQUIRED');
    if (!sca) blockers.push('SCA_PATH_REQUIRED');
    if (!limit) blockers.push('SCHEME_LIMIT_EVIDENCE_REQUIRED');
    return {
      environment: bool(this.env.ATLAS_DIRECT_SEPA_PRODUCTION) ? 'PRODUCTION' : 'SANDBOX',
      authenticated: psp && network,
      execution_authorized: psp && network && settlement && sca && limit,
      currency: 'EUR',
      max_amount_in_minor: Number.isFinite(max) ? Math.round(max * 100) : 0,
      blockers
    };
  }
  buildInitiationRequest({ intent, raw_beneficiary_iban, scheme = 'SCT' }) {
    if (!raw_beneficiary_iban) throw new Error('beneficiary_iban_required');
    if (!['SCT','SCT_INST'].includes(String(scheme))) throw new Error('sepa_scheme_invalid');
    return {
      schema: 'atlas-direct-sepa-instruction-v1', provider: 'atlas-direct-sepa', scheme: String(scheme),
      amount_in_minor: intent.amount_in_minor, currency: 'EUR',
      beneficiary_iban: String(raw_beneficiary_iban), beneficiary_name: intent.beneficiary_name,
      reference: intent.reference, idempotency_key: idempotencyKey(intent),
      intent_binding_sha256: intent.intent_binding_sha256,
      requires_explicit_owner_authorization: true,
      network_request_performed: false, value_moved: false
    };
  }
  normalizeStatus(resource = {}) { return String(resource.normalized_status || resource.status || 'UNKNOWN').toUpperCase(); }
}

module.exports.AdyenOutboundAdapter = AdyenOutboundAdapter;
module.exports.TinkOpenBankingAdapter = TinkOpenBankingAdapter;
module.exports.DirectSepaAdapter = DirectSepaAdapter;


function buildDefaultAdapters({ env = process.env } = {}) {
  return [
    new BunqNativeAdapter({ env }),
    new DirectSepaAdapter({ env }),
    new OwnPispAdapter({ env }),
    new AdyenOutboundAdapter({ env }),
    new YapilyConnectAdapter({ env }),
    new TinkOpenBankingAdapter({ env })
  ];
}
module.exports.buildDefaultAdapters = buildDefaultAdapters;
