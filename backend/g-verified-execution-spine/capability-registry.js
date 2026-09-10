'use strict';

const { ASSURANCE, ASSURANCE_RANK } = require('./states');

// A connector is the ONLY way the spine touches a real external or local
// effect. It must implement:
//
//   name                      unique capability id
//   assurance_ceiling         highest ASSURANCE this connector could ever reach
//   supportsReadback          boolean
//   async discover()          read-only capability probe. Returns
//                             { ok, observed_assurance, detail } . MUST NOT
//                             cause a state change.
//   async captureState(req)   returns a stable hash string for the target
//                             object's current state, or 'ABSENT'.
//   async execute(req)        performs the bounded effect. Returns
//                             { provider, provider_request_id, receipt,
//                               applied, raw_status } . On ambiguity it MUST
//                             throw; a thrown error may carry
//                             `provider_http_status` to signal a definite
//                             provider-side failure (vs. transport ambiguity).
//   async readback(req, exec) required when supportsReadback. Returns
//                             { verified, observed_status, binding_ok, detail }.
//
// `req` passed to the connector is the sanitized execution request:
//   { execution_id, request_id, actor, operation, params, idempotency_key,
//     scope, binding_sha256 }

class CapabilityRegistry {
  constructor() {
    this._connectors = new Map();
    this._disabled = new Set();
  }

  register(connector) {
    if (!connector || typeof connector !== 'object') {
      throw new Error('connector_invalid');
    }
    const name = String(connector.name || '');
    if (!name) throw new Error('connector_name_required');
    for (const fn of ['discover', 'captureState', 'execute']) {
      if (typeof connector[fn] !== 'function') {
        throw new Error(`connector_missing_${fn}`);
      }
    }
    if (connector.supportsReadback && typeof connector.readback !== 'function') {
      throw new Error('connector_missing_readback');
    }
    if (!(connector.assurance_ceiling in ASSURANCE_RANK)) {
      throw new Error('connector_assurance_ceiling_invalid');
    }
    if (this._connectors.has(name)) {
      throw new Error(`connector_already_registered:${name}`);
    }
    this._connectors.set(name, connector);
    return this;
  }

  disable(name) {
    this._disabled.add(String(name));
  }

  has(name) {
    return this._connectors.has(String(name)) && !this._disabled.has(String(name));
  }

  // Returns the connector or throws — callers translate the throw into
  // NO_VERIFIED_PATH. There is no "default" connector and no fuzzy matching.
  resolve(name) {
    const key = String(name || '');
    if (this._disabled.has(key)) throw new Error(`capability_disabled:${key}`);
    const connector = this._connectors.get(key);
    if (!connector) throw new Error(`capability_not_registered:${key}`);
    return connector;
  }

  list() {
    return [...this._connectors.keys()].map((name) => ({
      name,
      disabled: this._disabled.has(name),
      assurance_ceiling: this._connectors.get(name).assurance_ceiling,
      supportsReadback: !!this._connectors.get(name).supportsReadback,
    }));
  }
}

module.exports = { CapabilityRegistry, ASSURANCE };
