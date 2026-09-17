#!/usr/bin/env node
'use strict';

const { activationMatrix } = require('./atlas-payment-rail-activation');

const CONTRACTS = Object.freeze({
  'revolut-manual-evidence-v1': {
    rail_id:'revolut-manual-sca', executor:'OFFLINE_ACCOUNT_EVIDENCE_VERIFIER', network_probe:false,
    steps:['verify_current_revolut_account_evidence','verify_eur_payment_account','bind_fresh_evidence_hash'],
    non_financial_mutations:[], required_evidence:['provider_identity','account_product','currency','observed_at','source_reference']
  },
  'bunq-readonly-v1': {
    rail_id:'bunq-native-draft', executor:'G_SYSTEM_BUNQ_READONLY_CLIENT', network_probe:true,
    steps:['installation','device_registration','session','discover_eur_account','read_balance','verify_payment_capability_without_financial_write'],
    non_financial_mutations:['installation','device_registration','session'],
    required_evidence:['provider_request_ids','user_id','monetary_account_id','currency','balance_read','environment']
  },
  'revolut-open-banking-readonly-v1': {
    rail_id:'revolut-open-banking', executor:'NOT_INSTALLED', network_probe:true,
    steps:['verify_pisp_transport','discover_revolut_institution','verify_payment_initiation_support','verify_sca_redirect','verify_status_readback'],
    non_financial_mutations:[], required_evidence:['transport_provider','institution_id','pisp_capability','sca_path','readback_capability']
  },
  'adyen-readonly-v1': {
    rail_id:'adyen-api', executor:'NOT_INSTALLED', network_probe:true,
    steps:['authenticate_api_credential','read_balance_platform_context','calculate_bank_transfer_route','verify_webhook_readback_capability'],
    non_financial_mutations:[], required_evidence:['credential_identity','balance_account_id','verified_transfer_route','environment']
  },
  'tink-readonly-v1': {
    rail_id:'tink-open-banking', executor:'NOT_INSTALLED', network_probe:true,
    steps:['authenticate_client','discover_supported_institution','verify_payment_initiation_capability','verify_callback_readback'],
    non_financial_mutations:[], required_evidence:['provider_evidence_id','institution_id','pisp_capability','environment']
  },
  'yapily-readonly-v1': {
    rail_id:'yapily-connect', executor:'NOT_INSTALLED', network_probe:true,
    steps:['authenticate_application','list_institutions','verify_single_payment_feature','verify_registration_and_webhook_capability'],
    non_financial_mutations:[], required_evidence:['institution_id','feature_CREATE_DOMESTIC_SINGLE_PAYMENT','registration_state','environment']
  },
  'own-pisp-readonly-v1': {
    rail_id:'atlas-own-pisp', executor:'NOT_INSTALLED', network_probe:true,
    steps:['verify_dnb_authorisation','verify_eidas_identity','verify_bank_registration','read_bank_capabilities'],
    non_financial_mutations:[], required_evidence:['dnb_receipt','eidas_certificate_fingerprint','bank_registration_receipt','capability_readback']
  },
  'direct-sepa-readonly-v1': {
    rail_id:'atlas-direct-sepa', executor:'NOT_INSTALLED', network_probe:true,
    steps:['verify_psp_authorisation','verify_epc_adherence','verify_settlement_access','verify_network_reachability','verify_vop_controls'],
    non_financial_mutations:[], required_evidence:['psp_authorisation','epc_adherence','settlement_account','network_receipt','vop_receipt']
  }
});

function probePlan({rail_id, env = process.env, evidence = {}, now = new Date()} = {}) {
  const matrix = activationMatrix({env,evidence,now});
  const rail = matrix.rails.find(r => r.rail_id === rail_id);
  if (!rail) throw new Error('rail_not_found');
  const contract = CONTRACTS[rail.probe_contract];
  if (!contract) throw new Error('probe_contract_not_found');
  const operatorOptIn = String(env.ATLAS_ALLOW_READONLY_NETWORK_PROBE || '').toLowerCase() === 'true';
  return {
    schema:'atlas-payment-readonly-probe-plan-v2', rail_id,
    activation_state:rail.state, contract,
    can_run_offline_verification: rail.state === 'READY_FOR_MANUAL_ACCOUNT_VERIFICATION' && contract.network_probe === false,
    can_run_readonly_network_probe: rail.state === 'READY_FOR_READONLY_PROBE' && contract.network_probe === true && operatorOptIn && contract.executor !== 'NOT_INSTALLED',
    financial_writes_allowed:false,
    payment_endpoint_call_permitted:false,
    value_moved:false
  };
}

if (require.main === module) {
  const rail = process.argv[2] || 'revolut-manual-sca';
  console.log(JSON.stringify(probePlan({rail_id:rail}), null, 2));
}
module.exports = { CONTRACTS, probePlan };
