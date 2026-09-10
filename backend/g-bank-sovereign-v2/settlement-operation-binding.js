'use strict';

const { canonicalJson, sha256 } = require('./canonical');

function hash64(name, value) {
  const v = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) throw new Error(`${name}_invalid`);
  return v;
}

function settlementOperationBinding({ message_sha256, instruction_sha256, idempotency_key, promotion_certificate_sha256 } = {}) {
  const key = String(idempotency_key || '');
  if (!key || key.length > 256) throw new Error('settlement_operation_idempotency_key_invalid');
  const body = {
    schema: 'g-bank-settlement-operation-binding/v2',
    message_sha256: hash64('settlement_operation_message_sha256', message_sha256),
    instruction_sha256: hash64('settlement_operation_instruction_sha256', instruction_sha256),
    idempotency_key: key,
    promotion_certificate_sha256: hash64('settlement_operation_promotion_certificate_sha256', promotion_certificate_sha256),
    grants_external_rights: false,
    permits_value_movement_by_itself: false,
  };
  return Object.freeze({ ...body, operation_binding_sha256: sha256(canonicalJson(body)) });
}

module.exports = { settlementOperationBinding, hash64 };
