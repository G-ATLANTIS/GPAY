'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { sha256, canonicalJson } = require('../../g-bank-live-v1/canonical');

// A real, bounded, no-network capability. It performs a genuine local state
// change (append a record to a JSONL file inside its own root) and supports
// independent readback of that state. It is NOT a simulation: the effect is
// real and durable on disk, and readback re-reads the file it just wrote.
//
// Assurance ceiling is L4, but the honest classification for a local-only
// effect + local readback is L1 (see spine: local readback -> L1). It exists so
// the spine's full pipeline — including readback verification — can be exercised
// adversarially without touching any external provider or moving any value.
//
// Bounds: max record size, max total records. Operations: 'append-record'.

const DEFAULT_MAX_RECORD_BYTES = 4096;
const DEFAULT_MAX_RECORDS = 10_000;

class LocalFileCapability {
  constructor({
    name = 'local.file.append',
    rootDir,
    maxRecordBytes = DEFAULT_MAX_RECORD_BYTES,
    maxRecords = DEFAULT_MAX_RECORDS,
    // test seam: force an ambiguous failure AFTER the write has landed
    failAfterWrite = false,
  } = {}) {
    if (!rootDir) throw new Error('local_file_capability_rootDir_required');
    this.name = name;
    this.assurance_ceiling = 'L4';
    this.supportsReadback = true;
    this.rootDir = path.resolve(rootDir);
    this.maxRecordBytes = maxRecordBytes;
    this.maxRecords = maxRecords;
    this.failAfterWrite = failAfterWrite;
    fs.mkdirSync(this.rootDir, { recursive: true, mode: 0o700 });
  }

  _targetFile(params) {
    const bucket = String(params && params.bucket ? params.bucket : 'default');
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(bucket)) throw new Error('bucket_invalid');
    return path.join(this.rootDir, `${bucket}.jsonl`);
  }

  _readLines(file) {
    try {
      return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
    } catch (err) {
      if (err.code === 'ENOENT') return [];
      throw err;
    }
  }

  async discover() {
    // Read-only probe: confirm the root is writable by this process.
    try {
      fs.accessSync(this.rootDir, fs.constants.W_OK);
    } catch {
      return { ok: false, observed_assurance: 'L0', detail: 'root_not_writable' };
    }
    return { ok: true, observed_assurance: 'L1', detail: 'local capability verified' };
  }

  async captureState({ params } = {}) {
    const file = this._targetFile(params);
    const lines = this._readLines(file);
    if (lines.length === 0) return 'ABSENT';
    return sha256(canonicalJson({ count: lines.length, head: lines[0], tail: lines[lines.length - 1] }));
  }

  async execute({ params, binding_sha256, idempotency_key }) {
    const record = params && params.record;
    if (record === undefined) throw new Error('params_record_required');
    const encoded = JSON.stringify(record);
    if (Buffer.byteLength(encoded) > this.maxRecordBytes) {
      const err = new Error('record_exceeds_bounded_size');
      err.provider_http_status = 413; // definite rejection, not ambiguity
      throw err;
    }
    const file = this._targetFile(params);
    const existing = this._readLines(file);
    if (existing.length >= this.maxRecords) {
      const err = new Error('bucket_record_limit_reached');
      err.provider_http_status = 429;
      throw err;
    }

    const providerRequestId = crypto.randomUUID();
    const row = {
      provider_request_id: providerRequestId,
      binding_sha256: binding_sha256 || null,
      idempotency_key_sha256: sha256(String(idempotency_key || '')),
      record,
      applied_at: new Date().toISOString(),
    };
    const fd = fs.openSync(file, 'a', 0o600);
    try {
      fs.writeSync(fd, JSON.stringify(row) + '\n');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }

    if (this.failAfterWrite) {
      // Ambiguous failure: the write landed but we report uncertainty (no
      // provider_http_status). Models "provider executed, caller unsure".
      throw new Error('local_file_ambiguous_after_write');
    }

    return {
      provider: this.name,
      provider_request_id: providerRequestId,
      receipt: { provider_request_id: providerRequestId, applied_at: row.applied_at, bucket: params.bucket || 'default' },
      applied: true,
      raw_status: 'APPLIED',
    };
  }

  async readback({ params, binding_sha256 }, exec) {
    const targetId = exec && exec.provider_request_id;
    const targetIdemHash = exec && exec.idempotency_key_sha256;
    if (!targetId && !targetIdemHash) {
      return { verified: false, binding_ok: false, observed_status: 'NO_CORRELATION', external: false };
    }
    const file = this._targetFile(params || {});
    const lines = this._readLines(file);
    for (const line of lines) {
      let row;
      try {
        row = JSON.parse(line);
      } catch {
        continue;
      }
      const match =
        (targetId && row.provider_request_id === targetId) ||
        (!targetId && targetIdemHash && row.idempotency_key_sha256 === targetIdemHash);
      if (match) {
        const bindingOk = binding_sha256 == null || row.binding_sha256 === binding_sha256;
        return {
          verified: true,
          binding_ok: bindingOk,
          observed_status: 'APPLIED',
          external: false, // local readback only
          detail: { applied_at: row.applied_at, provider_request_id: row.provider_request_id },
        };
      }
    }
    return { verified: false, binding_ok: false, observed_status: 'NOT_FOUND', external: false };
  }
}

module.exports = { LocalFileCapability };
