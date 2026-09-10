'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { VelocityStore } = require('../g-bank-sovereign-v2/velocity-store');

const H = c => c.repeat(64);
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-velocity-'));
const store = new VelocityStore(root);
const day = '2026-09-10';

const first = store.reserve({
  idempotencyKey: 'idem-1',
  accountId: 'G:CUSTOMER:001',
  currency: 'EUR',
  instructionSha256: H('a'),
  amountMinor: 6000,
  maxDailyMinor: 10000,
  day,
  now: Date.parse('2026-09-10T06:00:00Z'),
});
assert.equal(first.state, 'RESERVED');
assert.equal(first.day, day);
assert.equal(store.snapshot({ accountId: 'G:CUSTOMER:001', currency: 'EUR', day }).committed_minor, 6000);

assert.throws(() => store.reserve({
  idempotencyKey: 'idem-2',
  accountId: 'G:CUSTOMER:001',
  currency: 'EUR',
  instructionSha256: H('b'),
  amountMinor: 5000,
  maxDailyMinor: 10000,
  day,
}), /daily_amount_limit_exceeded_atomic/);

const replay = store.reserve({
  idempotencyKey: 'idem-1',
  accountId: 'G:CUSTOMER:001',
  currency: 'EUR',
  instructionSha256: H('a'),
  amountMinor: 6000,
  maxDailyMinor: 10000,
  day,
});
assert.equal(replay.idempotent_replay, true);
assert.equal(store.snapshot({ accountId: 'G:CUSTOMER:001', currency: 'EUR', day }).committed_minor, 6000);

store.transition({
  idempotencyKey: 'idem-1',
  accountId: 'G:CUSTOMER:001',
  currency: 'EUR',
  day,
  to: 'RELEASED',
});
assert.equal(store.snapshot({ accountId: 'G:CUSTOMER:001', currency: 'EUR', day }).committed_minor, 0);

store.reserve({
  idempotencyKey: 'idem-2',
  accountId: 'G:CUSTOMER:001',
  currency: 'EUR',
  instructionSha256: H('b'),
  amountMinor: 5000,
  maxDailyMinor: 10000,
  day,
});
store.transition({
  idempotencyKey: 'idem-2',
  accountId: 'G:CUSTOMER:001',
  currency: 'EUR',
  day,
  to: 'SETTLED',
  now: Date.parse('2026-09-11T00:05:00Z'),
});
assert.equal(store.snapshot({ accountId: 'G:CUSTOMER:001', currency: 'EUR', day }).committed_minor, 5000);
assert.equal(store.snapshot({ accountId: 'G:CUSTOMER:001', currency: 'EUR', day: '2026-09-11' }).committed_minor, 0);

const files = fs.readdirSync(root).filter(n => n.endsWith('.json'));
assert.ok(files.length >= 1);
const target = path.join(root, files[0]);
const doc = JSON.parse(fs.readFileSync(target, 'utf8'));
doc.reservations[0].amount_minor += 1;
fs.writeFileSync(target, JSON.stringify(doc, null, 2) + '\n');
assert.throws(() => store.snapshot({ accountId: 'G:CUSTOMER:001', currency: 'EUR', day }), /velocity_state_hash_mismatch/);

console.log('G-BANK sovereign v2 velocity tests: PASS');
