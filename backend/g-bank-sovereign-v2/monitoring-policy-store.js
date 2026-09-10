'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { canonicalJson, sha256 } = require('./canonical');

function verifyPolicyHash(policy) {
  if (!policy || policy.schema !== 'g-bank-continuous-monitoring-policy/v2') throw new Error('monitoring_policy_required');
  const supplied = String(policy.policy_sha256 || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) throw new Error('monitoring_policy_hash_invalid');
  const { policy_sha256, ...body } = policy;
  if (sha256(canonicalJson(body)) !== supplied) throw new Error('monitoring_policy_hash_mismatch');
  if (!Number.isSafeInteger(Number(policy.epoch)) || Number(policy.epoch) <= 0) throw new Error('monitoring_policy_epoch_invalid');
  if (!Number.isFinite(Date.parse(policy.effective_from))) throw new Error('monitoring_policy_effective_from_invalid');
  return policy;
}

class MonitoringPolicyStore {
  constructor(directory) {
    this.directory = path.resolve(directory);
    this.lockPath = path.join(this.directory, '.lock');
    fs.mkdirSync(this.directory, { recursive: true, mode: 0o700 });
  }

  _files() {
    return fs.readdirSync(this.directory)
      .filter(name => /^epoch-[0-9]{8}\.json$/.test(name))
      .sort();
  }

  verify() {
    const policies = [];
    let priorEffective = -Infinity;
    let policyId = null;
    for (const [index, name] of this._files().entries()) {
      const policy = JSON.parse(fs.readFileSync(path.join(this.directory, name), 'utf8'));
      verifyPolicyHash(policy);
      if (policy.epoch !== index + 1) throw new Error('monitoring_policy_store_epoch_gap');
      if (name !== `epoch-${String(policy.epoch).padStart(8, '0')}.json`) throw new Error('monitoring_policy_store_filename_mismatch');
      if (policyId === null) policyId = policy.policy_id;
      if (policy.policy_id !== policyId) throw new Error('monitoring_policy_store_policy_id_changed');
      const effective = Date.parse(policy.effective_from);
      if (effective <= priorEffective) throw new Error('monitoring_policy_store_effective_time_not_monotonic');
      priorEffective = effective;
      policies.push(policy);
    }
    const rootRows = policies.map(policy => ({ epoch: policy.epoch, policy_sha256: policy.policy_sha256 }));
    return Object.freeze({
      verified: true,
      policy_count: policies.length,
      latest_epoch: policies.length ? policies[policies.length - 1].epoch : 0,
      latest_policy_sha256: policies.length ? policies[policies.length - 1].policy_sha256 : null,
      policy_root_sha256: sha256(canonicalJson(rootRows)),
    });
  }

  commit(policy) {
    verifyPolicyHash(policy);
    let fd;
    try { fd = fs.openSync(this.lockPath, 'wx', 0o600); }
    catch (err) {
      if (err.code === 'EEXIST') throw new Error('monitoring_policy_store_busy');
      throw err;
    }
    try {
      const before = this.verify();
      const expectedEpoch = before.latest_epoch + 1;
      if (policy.epoch !== expectedEpoch) throw new Error('monitoring_policy_store_next_epoch_required');
      if (before.latest_policy_sha256) {
        const prior = this.get(before.latest_epoch);
        if (policy.policy_id !== prior.policy_id) throw new Error('monitoring_policy_store_policy_id_changed');
        if (Date.parse(policy.effective_from) <= Date.parse(prior.effective_from)) throw new Error('monitoring_policy_store_effective_time_not_monotonic');
      }
      const file = path.join(this.directory, `epoch-${String(policy.epoch).padStart(8, '0')}.json`);
      fs.writeFileSync(file, JSON.stringify(policy, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
      const out = fs.openSync(file, 'r');
      try { fs.fsyncSync(out); } finally { fs.closeSync(out); }
      this.verify();
      return Object.freeze({ ...policy });
    } finally {
      try { fs.closeSync(fd); } catch {}
      try { fs.unlinkSync(this.lockPath); } catch {}
    }
  }

  get(epoch) {
    const ep = Number(epoch);
    if (!Number.isSafeInteger(ep) || ep <= 0) throw new Error('monitoring_policy_store_epoch_invalid');
    const file = path.join(this.directory, `epoch-${String(ep).padStart(8, '0')}.json`);
    if (!fs.existsSync(file)) throw new Error('monitoring_policy_store_epoch_not_found');
    const policy = JSON.parse(fs.readFileSync(file, 'utf8'));
    verifyPolicyHash(policy);
    return Object.freeze(policy);
  }

  active({ now = Date.now() } = {}) {
    const policies = this._files().map(name => JSON.parse(fs.readFileSync(path.join(this.directory, name), 'utf8')));
    for (const policy of policies) verifyPolicyHash(policy);
    const eligible = policies.filter(policy => Date.parse(policy.effective_from) <= now + 30000);
    if (!eligible.length) throw new Error('monitoring_policy_store_no_active_policy');
    return Object.freeze({ ...eligible[eligible.length - 1] });
  }
}

module.exports = { MonitoringPolicyStore, verifyPolicyHash };
