'use strict';

const crypto = require('node:crypto');

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((out, key) => {
      out[key] = stable(value[key]);
      return out;
    }, {});
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(stable(value));
}

function sha256(value) {
  return crypto.createHash('sha256').update(
    Buffer.isBuffer(value) ? value : String(value),
  ).digest('hex');
}

function newIdempotencyKey() {
  return crypto.randomUUID();
}

module.exports = { stable, canonicalJson, sha256, newIdempotencyKey };
