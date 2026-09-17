#!/usr/bin/env node
'use strict';

const TEST_PAYMENT_ID = '0afd1f6a-f611-48ce-9488-321129bb3a70';

async function fetchStatus(fetchImpl, url) {
  try {
    const response = await fetchImpl(url, {
      method: 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(10000)
    });
    const text = await response.text();
    return {
      url,
      http_status: response.status,
      ok: response.status >= 200 && response.status < 300,
      body: text.slice(0, 2048)
    };
  } catch (error) {
    return { url, http_status: null, ok: false, error: String(error.message || error) };
  }
}

function webhookEnvironment(body) {
  try {
    const parsed = JSON.parse(body);
    return String(parsed.environment || '').toLowerCase() || null;
  } catch {
    return null;
  }
}
async function evaluateNetworkReadiness({
  base_url = 'https://bank.gijs.live',
  fetch_impl = globalThis.fetch
} = {}) {
  if (typeof fetch_impl !== 'function') throw new Error('fetch_unavailable');
  const base = String(base_url).replace(/\/$/, '');
  const webhook = await fetchStatus(fetch_impl, `${base}/api/open-banking/webhook`);
  const returned = await fetchStatus(
    fetch_impl,
    `${base}/api/open-banking/return?payment_id=${TEST_PAYMENT_ID}`
  );

  const env = webhookEnvironment(webhook.body || '');
  const blockers = [];
  if (!webhook.ok) blockers.push('PUBLIC_WEBHOOK_UNREACHABLE');
  if (!returned.ok) blockers.push('PUBLIC_RETURN_URI_UNREACHABLE');
  if (webhook.ok && env !== 'live') blockers.push('PUBLIC_WEBHOOK_NOT_LIVE_ENV');

  return {
    schema: 'atlas-payment-network-readiness-v2',
    base_url: base,
    webhook_http_status: webhook.http_status,
    return_http_status: returned.http_status,
    webhook_environment: env,
    state: blockers.length === 0 ? 'READY' : 'BLOCKED',
    blockers,
    payment_endpoint_called: false,
    payment_created: false,
    value_moved: false
  };
}
async function main() {
  const baseUrl = process.argv[2] || 'https://bank.gijs.live';
  const result = await evaluateNetworkReadiness({ base_url: baseUrl });
  console.log(JSON.stringify(result, null, 2));
  if (result.state !== 'READY') process.exitCode = 2;
  return result;
}

if (require.main === module) {
  main().catch(error => {
    console.error(String(error.message || error));
    process.exitCode = 2;
  });
}

module.exports = {
  TEST_PAYMENT_ID,
  fetchStatus,
  webhookEnvironment,
  evaluateNetworkReadiness,
  main
};
