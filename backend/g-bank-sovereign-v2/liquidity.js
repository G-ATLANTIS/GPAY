'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function nonNegative(name, value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${name}_invalid`);
  return n;
}

function assessLiquidity({ immediately_available_minor, pending_outbound_minor = 0, stressed_outflow_minor = 0, minimum_buffer_minor = 0, now = Date.now() }) {
  const available = nonNegative('immediately_available_minor', immediately_available_minor);
  const pending = nonNegative('pending_outbound_minor', pending_outbound_minor);
  const stressed = nonNegative('stressed_outflow_minor', stressed_outflow_minor);
  const buffer = nonNegative('minimum_buffer_minor', minimum_buffer_minor);
  const required = pending + stressed + buffer;
  if (!Number.isSafeInteger(required)) throw new Error('liquidity_requirement_overflow');
  const headroom = available - required;

  const body = {
    schema: 'g-bank-liquidity-assessment/v2',
    state: headroom >= 0 ? 'PASS' : 'BLOCK',
    immediately_available_minor: available,
    pending_outbound_minor: pending,
    stressed_outflow_minor: stressed,
    minimum_buffer_minor: buffer,
    required_liquidity_minor: required,
    headroom_minor: headroom,
    assessed_at: new Date(now).toISOString(),
  };
  return Object.freeze({ ...body, assessment_sha256: sha256(canonicalJson(body)) });
}

module.exports = { assessLiquidity };
