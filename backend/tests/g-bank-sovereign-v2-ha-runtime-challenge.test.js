'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { HARuntimeChallengeStore } = require('../g-bank-sovereign-v2/ha-runtime-challenge-store');

const NOW = Date.parse('2026-09-10T11:30:00.000Z');
const H = c => c.repeat(64);
const OP = H('1');

(() => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-ha-challenge-v2-'));
  const store = new HARuntimeChallengeStore(path.join(root, 'challenges.jsonl'));
  const challenge = store.issue({ operation_binding_sha256: OP, ttl_ms: 30000, now: NOW });
  assert.match(challenge.nonce_sha256, /^[0-9a-f]{64}$/);
  assert.equal(challenge.operation_binding_sha256, OP);
  assert.equal(store.verify().issued_count, 1);
  assert.equal(store.assertUsable({ nonce_sha256: challenge.nonce_sha256, operation_binding_sha256: OP, now: NOW + 1000 }).issue_record_sha256, challenge.issue_record_sha256);

  const consumed = store.consume({ nonce_sha256: challenge.nonce_sha256, operation_binding_sha256: OP, observation_sha256: H('a'), now: NOW + 1000 });
  assert.match(consumed.consume_record_sha256, /^[0-9a-f]{64}$/);
  assert.equal(consumed.operation_binding_sha256, OP);
  assert.equal(store.verify().consumed_count, 1);
  assert.throws(() => store.assertUsable({ nonce_sha256: challenge.nonce_sha256, operation_binding_sha256: OP, now: NOW + 1000 }), /ha_runtime_challenge_replay/);
  assert.throws(() => store.consume({ nonce_sha256: challenge.nonce_sha256, operation_binding_sha256: OP, observation_sha256: H('a'), now: NOW + 1000 }), /ha_runtime_challenge_replay/);
})();

(() => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-ha-challenge-cross-op-v2-'));
  const store = new HARuntimeChallengeStore(path.join(root, 'challenges.jsonl'));
  const challenge = store.issue({ operation_binding_sha256: OP, ttl_ms: 30000, now: NOW });
  assert.throws(() => store.assertUsable({ nonce_sha256: challenge.nonce_sha256, operation_binding_sha256: H('2'), now: NOW + 1000 }), /ha_runtime_challenge_operation_binding_mismatch/);
  assert.throws(() => store.consume({ nonce_sha256: challenge.nonce_sha256, operation_binding_sha256: H('2'), observation_sha256: H('a'), now: NOW + 1000 }), /ha_runtime_challenge_operation_binding_mismatch/);
  assert.equal(store.verify().consumed_count, 0, 'wrong operation must never consume the challenge');
})();

(() => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-ha-challenge-exp-v2-'));
  const store = new HARuntimeChallengeStore(path.join(root, 'challenges.jsonl'));
  const challenge = store.issue({ operation_binding_sha256: OP, ttl_ms: 5000, now: NOW });
  assert.throws(() => store.assertUsable({ nonce_sha256: challenge.nonce_sha256, operation_binding_sha256: OP, now: NOW + 5000 }), /ha_runtime_challenge_expired/);
  assert.throws(() => store.consume({ nonce_sha256: challenge.nonce_sha256, operation_binding_sha256: OP, observation_sha256: H('b'), now: NOW + 5000 }), /ha_runtime_challenge_expired/);
})();

(() => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-ha-challenge-tamper-v2-'));
  const file = path.join(root, 'challenges.jsonl');
  const store = new HARuntimeChallengeStore(file);
  store.issue({ operation_binding_sha256: OP, now: NOW });
  const rows = fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse);
  rows[0].operation_binding_sha256 = H('3');
  fs.writeFileSync(file, rows.map(JSON.stringify).join('\n') + '\n');
  assert.throws(() => store.verify(), /ha_runtime_challenge_record_hash_mismatch/);
})();

(() => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-ha-challenge-link-v2-'));
  const target = path.join(root, 'target.jsonl');
  fs.writeFileSync(target, '');
  const link = path.join(root, 'link.jsonl');
  fs.symlinkSync(target, link);
  const store = new HARuntimeChallengeStore(link);
  assert.throws(() => store.verify(), /ha_runtime_challenge_store_file_invalid/);
})();

(() => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-ha-challenge-unissued-v2-'));
  const store = new HARuntimeChallengeStore(path.join(root, 'challenges.jsonl'));
  assert.throws(() => store.assertUsable({ nonce_sha256: H('c'), operation_binding_sha256: OP, now: NOW }), /ha_runtime_challenge_not_issued/);
})();

console.log('G-BANK sovereign v2 transaction-bound HA runtime challenge tests: PASS');
