'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'g-bank-cli-v2-'));
const marker = path.join(root, 'transport-loaded.marker');
const transport = path.join(root, 'transport.js');
fs.writeFileSync(transport, `'use strict';\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)}, 'LOADED');\nmodule.exports = {};\n`, { mode: 0o600 });

const script = path.resolve(__dirname, '../../scripts/g-bank-sovereign-v2.js');
const dummy = path.join(root, 'does-not-need-to-exist.json');
const baseArgs = [
  script, 'execute',
  '--prepared', dummy,
  '--validation', dummy,
  '--approval', dummy,
  '--signatures', dummy,
  '--idempotency-key', '00000000-0000-4000-8000-000000000001',
  '--readiness', dummy,
  '--promotion', dummy,
  '--promotion-sha256', 'a'.repeat(64),
];
const baseEnv = {
  ...process.env,
  G_BANK_SETTLEMENT_TRANSPORT_MODULE: transport,
};

(() => {
  const result = spawnSync(process.execPath, baseArgs, { env: baseEnv, encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--runtime-ha-attestation --runtime-ha-observer_required/);
  assert.equal(fs.existsSync(marker), false, 'transport module must not load when runtime HA arguments are absent');
})();

(() => {
  const result = spawnSync(process.execPath, [...baseArgs, '--runtime-ha-attestation', dummy], { env: baseEnv, encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--runtime-ha-attestation --runtime-ha-observer_required/);
  assert.equal(fs.existsSync(marker), false, 'transport module must not load when trusted runtime observer is absent');
})();

console.log('G-BANK sovereign v2 CLI runtime-HA contract tests: PASS');
