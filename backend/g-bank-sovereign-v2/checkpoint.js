'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');

function hashFile(file) {
  if (!file || !fs.existsSync(file)) return null;
  return sha256(fs.readFileSync(file));
}

function hashDirectory(dir) {
  if (!dir || !fs.existsSync(dir)) return sha256('EMPTY');
  const rows = fs.readdirSync(dir, { withFileTypes: true })
    .filter(e => e.isFile() && e.name.endsWith('.json'))
    .map(e => ({ name: e.name, sha256: hashFile(path.join(dir, e.name)) }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return sha256(canonicalJson(rows));
}

function snapshotState({
  accountRegistryPath,
  customerRegistryPath = null,
  ledgerPath,
  receiptsPath,
  executionsDir,
  velocityDir = null,
  inboundStatePath = null,
  monitoringCasesPath = null,
  evidenceRevocationsPath = null,
  monitoringPolicyDir = null,
  now = Date.now(),
}) {
  const state = {
    schema: 'g-bank-sovereign-state-checkpoint/v2',
    account_registry_sha256: hashFile(accountRegistryPath),
    customer_registry_sha256: hashFile(customerRegistryPath),
    ledger_file_sha256: hashFile(ledgerPath),
    receipts_file_sha256: hashFile(receiptsPath),
    executions_root_sha256: hashDirectory(executionsDir),
    velocity_root_sha256: hashDirectory(velocityDir),
    inbound_state_sha256: hashFile(inboundStatePath),
    monitoring_cases_sha256: hashFile(monitoringCasesPath),
    evidence_revocations_sha256: hashFile(evidenceRevocationsPath),
    monitoring_policy_root_sha256: hashDirectory(monitoringPolicyDir),
    checkpointed_at: new Date(now).toISOString(),
  };
  const rootBody = {
    account_registry_sha256: state.account_registry_sha256,
    customer_registry_sha256: state.customer_registry_sha256,
    ledger_file_sha256: state.ledger_file_sha256,
    receipts_file_sha256: state.receipts_file_sha256,
    executions_root_sha256: state.executions_root_sha256,
    velocity_root_sha256: state.velocity_root_sha256,
    inbound_state_sha256: state.inbound_state_sha256,
    monitoring_cases_sha256: state.monitoring_cases_sha256,
    evidence_revocations_sha256: state.evidence_revocations_sha256,
    monitoring_policy_root_sha256: state.monitoring_policy_root_sha256,
  };
  state.state_root_sha256 = sha256(canonicalJson(rootBody));
  return Object.freeze(state);
}

function writeCheckpoint(filePath, checkpoint) {
  if (!checkpoint?.state_root_sha256) throw new Error('checkpoint_required');
  const file = path.resolve(filePath);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(checkpoint, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  const fd = fs.openSync(tmp, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, file);
  return file;
}

function verifyCheckpoint(checkpoint, paths) {
  if (!checkpoint || checkpoint.schema !== 'g-bank-sovereign-state-checkpoint/v2') throw new Error('checkpoint_invalid');
  const current = snapshotState({ ...paths, now: Date.parse(checkpoint.checkpointed_at) });
  const checks = {
    account_registry: current.account_registry_sha256 === checkpoint.account_registry_sha256,
    customer_registry: current.customer_registry_sha256 === checkpoint.customer_registry_sha256,
    ledger: current.ledger_file_sha256 === checkpoint.ledger_file_sha256,
    receipts: current.receipts_file_sha256 === checkpoint.receipts_file_sha256,
    executions: current.executions_root_sha256 === checkpoint.executions_root_sha256,
    velocity: current.velocity_root_sha256 === checkpoint.velocity_root_sha256,
    inbound_state: current.inbound_state_sha256 === checkpoint.inbound_state_sha256,
    monitoring_cases: current.monitoring_cases_sha256 === checkpoint.monitoring_cases_sha256,
    evidence_revocations: current.evidence_revocations_sha256 === checkpoint.evidence_revocations_sha256,
    monitoring_policy_root: current.monitoring_policy_root_sha256 === checkpoint.monitoring_policy_root_sha256,
    state_root: current.state_root_sha256 === checkpoint.state_root_sha256,
  };
  return Object.freeze({
    schema: 'g-bank-sovereign-checkpoint-verification/v2',
    verified: Object.values(checks).every(Boolean),
    checks,
    expected_state_root_sha256: checkpoint.state_root_sha256,
    current_state_root_sha256: current.state_root_sha256,
  });
}

module.exports = { hashFile, hashDirectory, snapshotState, writeCheckpoint, verifyCheckpoint };
