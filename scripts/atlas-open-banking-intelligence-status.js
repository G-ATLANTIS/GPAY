#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const { bridgeRouteDecision } = require('./atlas-open-banking-intelligence-bridge');

function readJson(path, label) {
  if (!path) throw new Error(`${label}_path_required`);
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

function statusFromFiles({ intentPath, routePath, attestationPath, now = new Date() }) {
  const intent = readJson(intentPath, 'intent');
  const routeDecision = readJson(routePath, 'route');
  const attestation = readJson(attestationPath, 'attestation');
  const bridge = bridgeRouteDecision({ routeDecision, attestation, intent, now });
  return {
    schema: 'atlas-open-banking-intelligence-status-v1',
    state: bridge.intelligence_valid ? 'INTELLIGENCE_VERIFIED' : 'INTELLIGENCE_BLOCKED',
    bridge,
    payment_endpoint_called: false,
    provider_call_permitted: false,
    value_moved: false
  };
}

if (require.main === module) {
  try {
    const report = statusFromFiles({
      intentPath: process.env.ATLAS_PAYMENT_INTENT_PATH,
      routePath: process.env.ATLAS_PAYMENT_ROUTE_DECISION_PATH,
      attestationPath: process.env.ATLAS_PAYMENT_INTELLIGENCE_ATTESTATION_PATH
    });
    console.log(JSON.stringify(report, null, 2));
  } catch (error) {
    console.log(JSON.stringify({
      schema: 'atlas-open-banking-intelligence-status-v1',
      state: 'INTELLIGENCE_BLOCKED',
      blocker: String(error && error.message || error),
      payment_endpoint_called: false,
      provider_call_permitted: false,
      value_moved: false
    }, null, 2));
    process.exitCode = 2;
  }
}

module.exports = { statusFromFiles };
