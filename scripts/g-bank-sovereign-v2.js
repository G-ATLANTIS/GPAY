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

function args(argv = process.argv.slice(2)) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const v = argv[i];
    if (v.startsWith('--')) out[v.slice(2)] = argv[++i];
    else out._.push(v);
  }
  return out;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(path.resolve(file), 'utf8'));
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
  const mod = require(resolved);
  const transport = typeof mod.createTransport === 'function' ? mod.createTransport({ env }) : mod.transport || mod;
  return new DirectSettlementAdapter({ transport, env, name: env.G_BANK_SETTLEMENT_ADAPTER_NAME || 'g-direct-settlement' });
}

function coreFor(a, { live = false } = {}) {
  const p = statePaths(a);
  const accounts = new AccountRegistry(p.accounts);
  const ledger = new SovereignLedger(p.ledger);
  const settlement = live ? loadSettlement(process.env) : nullSettlement();
  return { p, accounts, ledger, core: new GBankSovereignCore({ accounts, ledger, settlement, stateDir: p.root, env: process.env }) };
}

async function main() {
  const a = args();
  const command = a._[0];
  if (!command) throw new Error('command_required');

  if (command === 'register-account') {
    if (!a.json) throw new Error('--json_required');
    const { accounts } = coreFor(a);
    const account = accounts.register(readJson(a.json));
    console.log(JSON.stringify({ state: 'ACCOUNT_REGISTERED', account_id: account.account_id, currency: account.currency, iban_bound: Boolean(account.iban) }, null, 2));
    return;
  }

  if (command === 'verify-ledger') {
    const { ledger } = coreFor(a);
    console.log(JSON.stringify({ state: 'LEDGER_VERIFIED', ...ledger.verify() }, null, 2));
    return;
  }

  if (command === 'prepare') {
    if (!a.instruction || !a.compliance || !a.out) throw new Error('--instruction --compliance --out_required');
    const { core } = coreFor(a);
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

  if (command === 'execute') {
    if (!a.prepared || !a.validation || !a.approval || !a['idempotency-key']) throw new Error('--prepared --validation --approval --idempotency-key_required');
    const { core } = coreFor(a, { live: true });
    const result = await core.execute({
      prepared: readJson(a.prepared),
      schemeValidationEvidence: readJson(a.validation),
      approvalToken: fs.readFileSync(path.resolve(a.approval), 'utf8').trim(),
      idempotencyKey: a['idempotency-key'],
    });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (command === 'reconcile') {
    if (!a['idempotency-key']) throw new Error('--idempotency-key_required');
    const { core } = coreFor(a, { live: true });
    const result = await core.reconcile({ idempotencyKey: a['idempotency-key'] });
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  throw new Error(`unknown_command_${command}`);
}

main().catch(err => {
  console.error('G_BANK_SOVEREIGN_V2_BLOCKED =', err.message || String(err));
  process.exit(2);
});
