#!/usr/bin/env node
'use strict';

const fs = require('fs');
const { spawn } = require('child_process');
const { LocalHostAgent } = require('../backend/transmission/localHostAgent');

function execCommand({ command, args }) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { shell: false });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (data) => { stdout += data.toString(); });
    child.stderr.on('data', (data) => { stderr += data.toString(); });
    child.on('error', (error) => resolve({ ok: false, error: error.message, stdout, stderr }));
    child.on('close', (code) => resolve({ ok: code === 0, code, stdout, stderr }));
  });
}

async function listDevicePaths() {
  if (process.platform === 'win32') {
    return String(process.env.G_ETHER_SERIAL_PATHS || '').split(',').map((v) => v.trim()).filter(Boolean);
  }
  const dev = await fs.promises.readdir('/dev');
  return dev
    .filter((name) => /^(ttyUSB|ttyACM|cu\.|tty\.)/.test(name))
    .map((name) => `/dev/${name}`);
}

function arg(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

(async () => {
  const hostId = process.env.G_ETHER_HOST_ID || require('os').hostname();
  const agent = new LocalHostAgent({ hostId, listDevicePaths, commandExecutor: execCommand });
  const mode = process.argv[2] || 'evidence';

  if (mode === 'evidence') {
    const devices = await agent.enumerate();
    let reticulum;
    try { reticulum = await agent.probeReticulum(); }
    catch (error) { reticulum = { status: 'BLOCKED', transmitted: false, error: error.code || error.message }; }
    console.log(JSON.stringify({ hostId, status: 'OBSERVED_NO_EXECUTION', transmitted: false, devices, reticulum }, null, 2));
    return;
  }

  if (mode === 'send') {
    if (process.env.G_ETHER_ALLOW_TRANSMIT !== 'YES') {
      throw Object.assign(new Error('Set G_ETHER_ALLOW_TRANSMIT=YES locally to permit send mode'), { code: 'G_LOCAL_TRANSMIT_OPT_IN_REQUIRED' });
    }
    const destination = arg('--destination');
    const payload = arg('--payload');
    if (!destination || payload === null) throw new Error('--destination and --payload are required');
    const result = await agent.transmitReticulum({
      destination,
      payload,
      authorizationEvidence: { localOperatorOptIn: true, source: 'G_ETHER_ALLOW_TRANSMIT' },
      executionIntent: true,
    });
    console.log(JSON.stringify({ hostId, status: result.ok ? 'VERIFIED_EXECUTED' : 'VERIFIED_FAILED', transmitted: result.ok === true, result }, null, 2));
    return;
  }

  throw new Error('Usage: run-g-ether-host-agent.js evidence | send --destination <peer> --payload <text>');
})().catch((error) => {
  console.error(JSON.stringify({ status: 'VERIFIED_FAILED', transmitted: false, code: error.code || null, error: error.message }));
  process.exitCode = 1;
});
