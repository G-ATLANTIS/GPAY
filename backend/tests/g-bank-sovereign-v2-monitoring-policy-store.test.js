'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createMonitoringPolicy } = require('../g-bank-sovereign-v2/monitoring-policy');
const { MonitoringPolicyStore } = require('../g-bank-sovereign-v2/monitoring-policy-store');

const NOW = Date.parse('2026-09-10T09:00:00.000Z');
const tx = {
  review_single_minor: 100000,
  suspend_single_minor: 500000,
  review_window_outbound_minor: 250000,
  suspend_window_outbound_minor: 1000000,
  review_transaction_count: 20,
  review_new_counterparty_count: 5,
  review_rapid_sequence_count: 5,
  suspend_rapid_sequence_count: 20,
  review_return_or_recall_count: 3,
};
const sla = { LOW: 14400000, MEDIUM: 3600000, HIGH: 900000, CRITICAL: 300000 };
function policy(epoch, effective) {
  return createMonitoringPolicy({
    epoch,
    effective_from: new Date(effective).toISOString(),
    max_kyc_age_ms: 365 * 24 * 60 * 60 * 1000,
    max_screen_age_ms: 24 * 60 * 60 * 1000,
    transaction: tx,
    case_review_sla_ms: sla,
  });
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-monitor-policy-v2-'));
const store = new MonitoringPolicyStore(root);
const p1 = policy(1, NOW - 2 * 60 * 60 * 1000);
const p2 = policy(2, NOW + 60 * 60 * 1000);
store.commit(p1);
store.commit(p2);
const proof = store.verify();
assert.equal(proof.verified, true);
assert.equal(proof.policy_count, 2);
assert.equal(proof.latest_epoch, 2);
assert.equal(proof.latest_policy_sha256, p2.policy_sha256);
assert.match(proof.policy_root_sha256, /^[0-9a-f]{64}$/);
assert.equal(store.active({ now: NOW }).policy_sha256, p1.policy_sha256, 'future epoch must not activate early');
assert.equal(store.active({ now: NOW + 2 * 60 * 60 * 1000 }).policy_sha256, p2.policy_sha256);
assert.throws(() => store.commit(policy(4, NOW + 3 * 60 * 60 * 1000)), /next_epoch/);
assert.throws(() => store.commit(policy(3, NOW)), /effective_time_not_monotonic/);

const file2 = path.join(root, 'epoch-00000002.json');
const tampered = JSON.parse(fs.readFileSync(file2, 'utf8'));
tampered.max_screen_age_ms += 1;
fs.writeFileSync(file2, JSON.stringify(tampered, null, 2) + '\n');
assert.throws(() => store.verify(), /hash_mismatch/);

console.log('G-BANK sovereign v2 monitoring policy store tests: PASS');
