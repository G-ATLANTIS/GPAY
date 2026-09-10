#!/usr/bin/env node
'use strict';

// G-BANK-CANONICAL-LIVE-ROUTING-P0 — static bypass guard.
//
// Fails (exit 1) if application/runtime code reaches a live provider mutation
// without going through G_VERIFIED_EXECUTION_SPINE. Scans backend/** and
// scripts/** .js files and rejects, outside a small explicit allowlist:
//
//   * importing the raw provider adapter (providers/mollie-live, MollieLiveAdapter)
//   * importing spine connectors directly (…/g-verified-execution-spine/connectors/…)
//   * `mollieClient.payments.create` / `@mollie/api-client` create calls
//   * `new GBankLiveCore(` (retired second execution authority)
//
// Allowlisted files are the spine internals, the connector implementations, the
// adapter itself, the sanctioned operator CLI, and tests that specifically
// exercise connector isolation.

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');

const SCAN_DIRS = ['backend', 'scripts'];

// Files allowed to touch the low-level primitives.
const ALLOWLIST = new Set(
  [
    // spine internals + connector implementations
    'backend/g-verified-execution-spine/connectors/mollie-spine-connector.js',
    'backend/g-verified-execution-spine/connectors/local-file.js',
    'backend/g-verified-execution-spine/gbank-mollie-routing.js',
    'backend/g-verified-execution-spine/index.js',
    // the adapter itself
    'backend/g-bank-live-v1/providers/mollie-live.js',
    // sanctioned operator CLI (imports adapter only to hand it to the spine)
    'scripts/g-bank-live-v1.js',
    // sanctioned HTTP route (routes through executeVerified)
    'backend/routes/mollie.js',
    // this guard
    'scripts/ci/check-spine-bypass.js',
    // tests that deliberately test isolation / the adapter in isolation
    'backend/tests/g-bank-live-v1.test.js',
    'backend/tests/g-verified-execution-spine.test.js',
    'backend/tests/g-bank-canonical-live-routing.test.js',
    'backend/tests/mollie-connector-isolation.test.js',
    'backend/tests/banking-smoke.test.js',
  ].map((p) => p.replace(/\//g, path.sep)),
);

const RULES = [
  {
    id: 'raw-mollie-adapter-import',
    re: /require\(\s*['"][^'"]*g-bank-live-v1\/providers\/mollie-live['"]\s*\)|\bMollieLiveAdapter\b/,
  },
  {
    id: 'spine-connector-direct-import',
    re: /require\(\s*['"][^'"]*g-verified-execution-spine\/connectors\/[^'"]+['"]\s*\)/,
  },
  {
    // Direct Mollie provider MUTATIONS (create / cancel payment, create refund).
    // Reads (.payments.get) are not flagged here, but a bare @mollie/api-client
    // import in non-allowlisted code is reported as a warning-level smell too.
    id: 'mollie-client-mutation',
    re: /\.payments\s*\.\s*(create|cancel)\s*\(|\.refunds\s*\.\s*create\s*\(/,
  },
  {
    id: 'raw-mollie-client-import',
    re: /require\(\s*['"]@mollie\/api-client['"]\s*\)/,
  },
  { id: 'retired-gbank-live-core', re: /new\s+GBankLiveCore\s*\(/ },
];

// --self-test: prove the rules catch known-bad and pass known-good, without
// touching the filesystem. Used by the routing test suite.
if (process.argv.includes('--self-test')) {
  const bad = [
    "const { MollieLiveAdapter } = require('../g-bank-live-v1/providers/mollie-live');",
    "require('../g-verified-execution-spine/connectors/mollie-spine-connector')",
    'await mollieClient.payments.create({ amount });',
    'const p = await client.payments.create({});',
    'new GBankLiveCore({ adapters })',
    "require('@mollie/api-client')",
  ];
  const good = [
    "const { executeVerified } = require('../g-verified-execution-spine/spine');",
    'const r = await mollieClient.payments.get(id);',
    'buildMollieRegistry({ env });',
  ];
  let failed = 0;
  for (const line of bad) {
    if (!RULES.some((r) => r.re.test(line))) {
      console.error('SELF-TEST: rule failed to catch bad line:', line);
      failed += 1;
    }
  }
  for (const line of good) {
    if (RULES.some((r) => r.re.test(line))) {
      console.error('SELF-TEST: rule wrongly flagged good line:', line);
      failed += 1;
    }
  }
  if (failed) process.exit(1);
  console.log('SPINE BYPASS GUARD SELF-TEST: PASS');
  process.exit(0);
}

function walk(dir, acc) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, acc);
    else if (entry.isFile() && entry.name.endsWith('.js')) acc.push(full);
  }
  return acc;
}

const violations = [];
for (const rel of SCAN_DIRS) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) continue;
  for (const file of walk(abs, [])) {
    const relPath = path.relative(ROOT, file);
    if (ALLOWLIST.has(relPath)) continue;
    const text = fs.readFileSync(file, 'utf8');
    text.split('\n').forEach((line, i) => {
      // ignore comment-only lines
      const code = line.replace(/\/\/.*$/, '');
      for (const rule of RULES) {
        if (rule.re.test(code)) {
          violations.push({ file: relPath, line: i + 1, rule: rule.id, text: line.trim().slice(0, 160) });
        }
      }
    });
  }
}

if (violations.length) {
  console.error('SPINE BYPASS GUARD: FAIL');
  for (const v of violations) {
    console.error(`  ${v.file}:${v.line}  [${v.rule}]  ${v.text}`);
  }
  console.error(
    `\n${violations.length} forbidden reference(s). Route live provider mutation through executeVerified() ` +
      'or add the file to the allowlist in scripts/ci/check-spine-bypass.js with justification.',
  );
  process.exit(1);
}

console.log(`SPINE BYPASS GUARD: PASS (scanned ${SCAN_DIRS.join(', ')}, allowlist ${ALLOWLIST.size} files)`);
