#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { AccountRegistry } = require('../backend/g-bank-sovereign-v2/accounts');
const { SovereignLedger } = require('../backend/g-bank-sovereign-v2/ledger');
const { DirectSettlementAdapter } = require('../backend/g-bank-sovereign-v2/direct-settlement');
const { GBankSovereignCore } = require('../backend/g-bank-sovereign-v2/sovereign-core');
const { createSovereignApproval } = require('../backend/g-bank-sovereign-v2/approval');
const { normalizePolicy } = require('../backend/g-bank-sovereign-v2/risk-policy');
const { normalizeAuthoritySet } = require('../backend/g-bank-sovereign-v2/authority');
const { assessSovereignReadiness } = require('../backend/g-bank-sovereign-v2/readiness');
const { createTechnicalPromotionCertificate } = require('../backend/g-bank-sovereign-v2/promotion-certificate');
const { verifyRuntimePromotionGate } = require('../backend/g-bank-sovereign-v2/runtime-promotion-gate');
const { HARuntimeChallengeStore } = require('../backend/g-bank-sovereign-v2/ha-runtime-challenge-store');
const { settlementOperationBinding } = require('../backend/g-bank-sovereign-v2/settlement-operation-binding');

function args(argv = process.argv.slice(2)) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const v = argv[i];
    if (v.startsWith('--')) {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) throw new Error(`${v}_value_required`);
      out[v.slice(2)] = next;
      i += 1;
    } else out._.push(v);
  }
  return out;
}

function sha256Arg(name, value) {
  const hash = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${name}_invalid`);
  return hash;
}

function readJson(file) {
  const resolved = path.resolve(String(file || ''));
  if (!file || !fs.existsSync(resolved)) throw new Error('json_file_required');
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('json_file_invalid');
  return JSON.parse(fs.readFileSync(resolved, 'utf8'));
}

function writePrivate(file, value) {
  const resolved = path.resolve(file);
  fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  fs.writeFileSync(resolved, typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  return resolved;
}

function statePaths(a) {
  const root = path.resolve(a['state-dir'] || process.env.G_BANK_SOVEREIGN_STATE_DIR || '.secrets/g-bank-sovereign-v2');
  return {
    root,
    accounts: path.resolve(a.accounts || path.join(root, 'accounts.json')),
    ledger: path.resolve(a.ledger || path.join(root, 'ledger.jsonl')),
    riskPolicy: path.resolve(a['risk-policy'] || process.env.G_BANK_RISK_POLICY_FILE || path.join(root, 'risk-policy.json')),
    authoritySet: path.resolve(a['authority-set'] || process.env.G_BANK_AUTHORITY_SET_FILE || path.join(root, 'authority-set.json')),
  };
}

function nullSettlement() {
  const blocked = async () => { throw new Error('settlement_transport_not_loaded'); };
  return { preflight: blocked, submit: blocked, readback: blocked };
}

function loadSettlement(env = process.env) {
  const modulePath = String(env.G_BANK_SETTLEMENT_TRANSPORT_MODULE || '');
  if (!modulePath) throw new Error('G_BANK_SETTLEMENT_TRANSPORT_MODULE_required');
  const resolved = path.resolve(modulePath);
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('G_BANK_SETTLEMENT_TRANSPORT_MODULE_invalid');
  const mod = require(resolved);
  const transport = typeof mod.createTransport === 'function' ? mod.createTransport({ env }) : mod.transport || mod;
  return new DirectSettlementAdapter({ transport, env, name: env.G_BANK_SETTLEMENT_ADAPTER_NAME || 'g-direct-settlement' });
}

function ephemeralNonExecutionGovernance() {
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  return {
    riskPolicy: normalizePolicy({}),
    authoritySet: normalizeAuthoritySet({
      authority_epoch: 1,
      operators: [{ operator_id: 'NONEXECUTION:EPHEMERAL', role: 'APPROVER', status: 'ACTIVE', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }).toString() }],
    }),
  };
}

function governanceFor(a, { required = true } = {}) {
  const p = statePaths(a);
  const havePolicy = fs.existsSync(p.riskPolicy);
  const haveAuthority = fs.existsSync(p.authoritySet);
  if (!required && (!havePolicy || !haveAuthority)) return ephemeralNonExecutionGovernance();
  if (!havePolicy) throw new Error('risk_policy_file_required');
  if (!haveAuthority) throw new Error('authority_set_file_required');
  return { riskPolicy: normalizePolicy(readJson(p.riskPolicy)), authoritySet: normalizeAuthoritySet(readJson(p.authoritySet)) };
}

function governanceSnapshot(riskPolicy, authoritySet) {
  return Object.freeze({
    policy_sha256: riskPolicy.policy_sha256,
    authority_set_sha256: authoritySet.authority_set_sha256,
    policy_epoch: riskPolicy.policy_epoch,
    authority_epoch: authoritySet.authority_epoch,
    normal_quorum: riskPolicy.normal_quorum,
    high_value_quorum: riskPolicy.high_value_quorum,
  });
}

function operationFromPrepared(prepared, idempotencyKey, promotionCertificateSha256) {
  if (!prepared?.iso20022?.document_sha256 || !prepared?.instruction?.instruction_sha256) throw new Error('prepared_settlement_binding_required');
  return settlementOperationBinding({
    message_sha256: prepared.iso20022.document_sha256,
    instruction_sha256: prepared.instruction.instruction_sha256,
    idempotency_key: idempotencyKey,
    promotion_certificate_sha256: promotionCertificateSha256,
  });
}

function configureRuntimePromotionArtifacts(a, env = process.env) {
  if (!a.readiness || !a.promotion || !a['promotion-sha256'] || !a['runtime-ha-attestation'] || !a['runtime-ha-observer'] || !a['runtime-ha-challenge-store']) {
    throw new Error('--readiness --promotion --promotion-sha256 --runtime-ha-attestation --runtime-ha-observer --runtime-ha-challenge-store_required');
  }
  env.G_BANK_RUNTIME_READINESS_FILE = path.resolve(a.readiness);
  env.G_BANK_RUNTIME_PROMOTION_CERTIFICATE_FILE = path.resolve(a.promotion);
  env.G_BANK_RUNTIME_HA_ATTESTATION_FILE = path.resolve(a['runtime-ha-attestation']);
  env.G_BANK_RUNTIME_HA_OBSERVER_FILE = path.resolve(a['runtime-ha-observer']);
  env.G_BANK_RUNTIME_HA_CHALLENGE_STORE = path.resolve(a['runtime-ha-challenge-store']);
  env.G_BANK_PROMOTION_CERTIFICATE_SHA256 = sha256Arg('promotion_sha256', a['promotion-sha256']);
  return Object.freeze({
    readiness_file: env.G_BANK_RUNTIME_READINESS_FILE,
    promotion_file: env.G_BANK_RUNTIME_PROMOTION_CERTIFICATE_FILE,
    runtime_ha_attestation_file: env.G_BANK_RUNTIME_HA_ATTESTATION_FILE,
    runtime_ha_observer_file: env.G_BANK_RUNTIME_HA_OBSERVER_FILE,
    runtime_ha_challenge_store: env.G_BANK_RUNTIME_HA_CHALLENGE_STORE,
    promotion_sha256: env.G_BANK_PROMOTION_CERTIFICATE_SHA256,
  });
}

function coreFor(a, { live = false, governanceRequired = false } = {}) {
  const p = statePaths(a);
  const accounts = new AccountRegistry(p.accounts);
  const ledger = new SovereignLedger(p.ledger);
  const settlement = live ? loadSettlement(process.env) : nullSettlement();
  const { riskPolicy, authoritySet } = governanceFor(a, { required: governanceRequired });
  return { p, accounts, ledger, riskPolicy, authoritySet, core: new GBankSovereignCore({ accounts, ledger, settlement, riskPolicy, authoritySet, stateDir: p.root, env: process.env }) };
}

async function main() {
  const a = args();
  const command = a._[0];
  if (!command) throw new Error('command_required');

  if (command === 'register-account') {
    if (!a.json) throw new Error('--json_required');
    const p = statePaths(a);
    const account = new AccountRegistry(p.accounts).register(readJson(a.json));
    console.log(JSON.stringify({ state: 'ACCOUNT_REGISTERED', account_id: account.account_id, currency: account.currency, iban_bound: Boolean(account.iban) }, null, 2));
    return;
  }

  if (command === 'verify-ledger') {
    const p = statePaths(a);
    console.log(JSON.stringify({ state: 'LEDGER_VERIFIED', ...new SovereignLedger(p.ledger).verify() }, null, 2));
    return;
  }

  if (command === 'issue-ha-challenge') {
    if (!a['challenge-store'] || !a.prepared || !a.promotion || !a['idempotency-key'] || !a.out) {
      throw new Error('--challenge-store --prepared --promotion --idempotency-key --out_required');
    }
    const prepared = readJson(a.prepared);
    const promotion = readJson(a.promotion);
    const promotionSha256 = sha256Arg('promotion_certificate_sha256', promotion.certificate_sha256);
    const operation = operationFromPrepared(prepared, a['idempotency-key'], promotionSha256);
    const store = new HARuntimeChallengeStore(a['challenge-store']);
    const challenge = store.issue({ operation_binding_sha256: operation.operation_binding_sha256, ttl_ms: a['ttl-ms'] === undefined ? 30000 : Number(a['ttl-ms']) });
    const output = writePrivate(a.out, {
      schema: 'g-bank-ha-runtime-challenge/v2', nonce_sha256: challenge.nonce_sha256,
      operation_binding_sha256: operation.operation_binding_sha256, message_sha256: operation.message_sha256,
      instruction_sha256: operation.instruction_sha256, idempotency_key: operation.idempotency_key,
      promotion_certificate_sha256: operation.promotion_certificate_sha256, issued_at: challenge.issued_at,
      expires_at: challenge.expires_at, issue_record_sha256: challenge.issue_record_sha256,
      grants_external_rights: false, permits_value_movement_by_itself: false,
    });
    console.log(JSON.stringify({ state: 'HA_RUNTIME_CHALLENGE_ISSUED', nonce_sha256: challenge.nonce_sha256, operation_binding_sha256: operation.operation_binding_sha256, issue_record_sha256: challenge.issue_record_sha256, expires_at: challenge.expires_at, challenge_store: path.resolve(a['challenge-store']), output, grants_external_rights: false, permits_value_movement_by_itself: false }, null, 2));
    return;
  }

  if (command === 'prepare') {
    if (!a.instruction || !a.compliance || !a.out) throw new Error('--instruction --compliance --out_required');
    const { core } = coreFor(a, { governanceRequired: false });
    const prepared = core.prepare({ rawInstruction: readJson(a.instruction), complianceBundle: readJson(a.compliance) });
    const output = writePrivate(a.out, prepared);
    console.log(JSON.stringify({ state: 'SOVEREIGN_PAYMENT_PREPARED', preparation_sha256: prepared.preparation_sha256, message_sha256: prepared.iso20022.document_sha256, output }, null, 2));
    return;
  }

  if (command === 'approve') {
    if (!a.prepared || !a.validation || !a.out) throw new Error('--prepared --validation --out_required');
    const key = a['idempotency-key'] || crypto.randomUUID();
    const token = createSovereignApproval({ prepared: readJson(a.prepared), schemeValidationEvidence: readJson(a.validation), idempotencyKey: key }, process.env);
    const output = writePrivate(a.out, token + '\n');
    console.log(JSON.stringify({ state: 'SOVEREIGN_PAYMENT_APPROVED', idempotency_key: key, approval_file: output }, null, 2));
    return;
  }

  if (command === 'readiness') {
    if (!a.prudential || !a['monitoring-audit'] || !a['recovery-audit'] || !a['ha-audit'] || !a['ha-deployment-audit'] || !a.out) throw new Error('--prudential --monitoring-audit --recovery-audit --ha-audit --ha-deployment-audit --out_required');
    const { riskPolicy, authoritySet } = governanceFor(a, { required: true });
    const settlement = loadSettlement(process.env);
    const preflight = await settlement.preflight();
    const readiness = assessSovereignReadiness({ env: process.env, transportPreflight: preflight, governance: governanceSnapshot(riskPolicy, authoritySet), prudential: readJson(a.prudential), monitoringAudit: readJson(a['monitoring-audit']), recoveryAudit: readJson(a['recovery-audit']), haAudit: readJson(a['ha-audit']), haDeploymentAudit: readJson(a['ha-deployment-audit']) });
    const output = writePrivate(a.out, readiness);
    console.log(JSON.stringify({ state: readiness.state, direct_live_ready: readiness.direct_live_ready, recovery_controls_verified: readiness.recovery_controls_verified, ha_controls_verified: readiness.ha_controls_verified, ha_deployment_verified: readiness.ha_deployment_verified, customer_monitoring_verified: readiness.customer_monitoring_verified, transport_preflight_receipt_sha256: readiness.evidence_bindings.transport_preflight_receipt_sha256, recovery_checkpoint_state_root_sha256: readiness.recovery_checkpoint_state_root_sha256, ha_checkpoint_state_root_sha256: readiness.ha_checkpoint_state_root_sha256, ha_voter_journal_root_sha256: readiness.ha_voter_journal_root_sha256, ha_cluster_authority_root_sha256: readiness.ha_cluster_authority_root_sha256, ha_fence_valid_until: readiness.ha_fence_valid_until, output }, null, 2));
    return;
  }

  if (command === 'promote') {
    if (!a.readiness || !a.checkpoint || !a['trusted-signing-key-binding-sha256'] || !a['trusted-runtime-ha-observer-sha256'] || !a.out) throw new Error('--readiness --checkpoint --trusted-signing-key-binding-sha256 --trusted-runtime-ha-observer-sha256 --out_required');
    const readiness = readJson(a.readiness);
    const checkpoint = readJson(a.checkpoint);
    const { riskPolicy, authoritySet } = governanceFor(a, { required: true });
    const certificate = createTechnicalPromotionCertificate({
      readiness, checkpoint, governance: governanceSnapshot(riskPolicy, authoritySet), evidence_bindings: readiness.evidence_bindings,
      trusted_signing_key_binding_sha256: sha256Arg('trusted_signing_key_binding_sha256', a['trusted-signing-key-binding-sha256']),
      trusted_runtime_ha_observer_sha256: sha256Arg('trusted_runtime_ha_observer_sha256', a['trusted-runtime-ha-observer-sha256']),
      ttl_seconds: a['ttl-seconds'] === undefined ? 120 : Number(a['ttl-seconds']),
    });
    const output = writePrivate(a.out, certificate);
    console.log(JSON.stringify({ state: certificate.state, certificate_sha256: certificate.certificate_sha256, state_root_sha256: certificate.state_root_sha256, policy_sha256: certificate.policy_sha256, authority_set_sha256: certificate.authority_set_sha256, trusted_runtime_ha_observer_sha256: certificate.trusted_runtime_ha_observer_sha256, recovery_audit_sha256: certificate.evidence_bindings.recovery_audit_sha256, ha_audit_sha256: certificate.evidence_bindings.ha_audit_sha256, ha_deployment_audit_sha256: certificate.evidence_bindings.ha_deployment_audit_sha256, ha_voter_journal_root_sha256: certificate.ha_voter_journal_root_sha256, ha_cluster_authority_root_sha256: certificate.ha_cluster_authority_root_sha256, customer_monitoring_audit_sha256: certificate.evidence_bindings.customer_monitoring_audit_sha256, ha_fence_valid_until: certificate.ha_fence_valid_until, expires_at: certificate.expires_at, output, grants_external_rights: certificate.grants_external_rights, permits_value_movement_by_itself: certificate.permits_value_movement_by_itself }, null, 2));
    return;
  }

  if (command === 'execute') {
    if (!a.prepared || !a.validation || !a.approval || !a.signatures || !a['idempotency-key'] || !a.readiness || !a.promotion || !a['promotion-sha256'] || !a['runtime-ha-attestation'] || !a['runtime-ha-observer'] || !a['runtime-ha-challenge-store']) throw new Error('--prepared --validation --approval --signatures --idempotency-key --readiness --promotion --promotion-sha256 --runtime-ha-attestation --runtime-ha-observer --runtime-ha-challenge-store_required');
    configureRuntimePromotionArtifacts(a, process.env);
    const prepared = readJson(a.prepared);
    const expectedOperation = { message_sha256: prepared?.iso20022?.document_sha256, instruction_sha256: prepared?.instruction?.instruction_sha256, idempotency_key: a['idempotency-key'] };
    const { core } = coreFor(a, { live: true, governanceRequired: true });
    const runtimeGate = verifyRuntimePromotionGate({ env: process.env, consumeChallenge: false, expectedOperation });
    const result = await core.execute({ prepared, schemeValidationEvidence: readJson(a.validation), approvalToken: fs.readFileSync(path.resolve(a.approval), 'utf8').trim(), authoritySignatures: readJson(a.signatures), idempotencyKey: a['idempotency-key'] });
    console.log(JSON.stringify({ ...result, settlement_operation_binding_sha256: runtimeGate.settlement_operation_binding_sha256, runtime_promotion_gate_sha256: runtimeGate.gate_sha256, trusted_runtime_ha_observer_sha256: runtimeGate.trusted_runtime_ha_observer_sha256, ha_runtime_attestation_audit_sha256: runtimeGate.ha_runtime_attestation_audit_sha256, ha_runtime_observation_sha256: runtimeGate.ha_runtime_observation_sha256, ha_runtime_challenge_nonce_sha256: runtimeGate.ha_runtime_challenge_nonce_sha256 }, null, 2));
    return;
  }

  if (command === 'reconcile') {
    if (!a['idempotency-key']) throw new Error('--idempotency-key_required');
    const { core } = coreFor(a, { live: true, governanceRequired: false });
    console.log(JSON.stringify(await core.reconcile({ idempotencyKey: a['idempotency-key'] }), null, 2));
    return;
  }

  throw new Error(`unknown_command_${command}`);
}

main().catch(err => {
  console.error('G_BANK_SOVEREIGN_V2_BLOCKED =', err.message || String(err));
  process.exit(2);
});
