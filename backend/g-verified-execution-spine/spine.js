'use strict';

const crypto = require('node:crypto');
const path = require('node:path');

const { canonicalJson, sha256 } = require('../g-bank-live-v1/canonical');
const { IdempotencyStore } = require('../g-bank-live-v1/idempotency-store');
const { ReceiptLedger } = require('../g-bank-live-v1/receipt-ledger');
const { SequenceStore } = require('./sequence-store');
const { verifyAuthorization } = require('./authorization');
const { safeEvidence } = require('./redaction');
const {
  RESULT_STATE,
  ASSURANCE,
  assuranceAtLeast,
  minAssurance,
  VERIFICATION_METHOD,
  CANONICAL_COMMIT_STATUS,
} = require('./states');

const SCHEMA = 'g-verified-execution-result/v1';

// -----------------------------------------------------------------------------
// Canonical request
// -----------------------------------------------------------------------------

function normalizeRequest(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('request_invalid');
  }
  const str = (v, name, { min = 1, max = 256 } = {}) => {
    const s = String(v == null ? '' : v);
    if (s.length < min || s.length > max) throw new Error(`${name}_invalid`);
    return s;
  };

  const scope = raw.scope && typeof raw.scope === 'object' ? raw.scope : {};
  const req = {
    schema: 'g-verified-execution-request/v1',
    request_id: str(raw.request_id, 'request_id', { min: 8, max: 128 }),
    actor: str(raw.actor, 'actor', { min: 2, max: 128 }),
    requested_capability: str(raw.requested_capability, 'requested_capability', { min: 2, max: 128 }),
    operation: str(raw.operation, 'operation', { min: 1, max: 128 }),
    params: raw.params && typeof raw.params === 'object' && !Array.isArray(raw.params) ? raw.params : {},
    idempotency_key: str(raw.idempotency_key, 'idempotency_key', { min: 8, max: 200 }),
    expected_sequence: Number(raw.expected_sequence),
    scope: {
      max_effects: Number(scope.max_effects),
      amount_minor:
        scope.amount_minor === undefined || scope.amount_minor === null ? null : Number(scope.amount_minor),
      note: scope.note ? str(scope.note, 'scope_note', { min: 1, max: 256 }) : null,
    },
    required_assurance: raw.required_assurance ? String(raw.required_assurance) : ASSURANCE.L1,
  };

  if (!Number.isSafeInteger(req.expected_sequence) || req.expected_sequence <= 0) {
    throw new Error('expected_sequence_invalid');
  }
  if (!(req.required_assurance in { L0: 1, L1: 1, L2: 1, L3: 1, L4: 1 })) {
    throw new Error('required_assurance_invalid');
  }
  return req;
}

// The binding hash authorization and idempotency are pinned to. `params` is
// included so a token cannot be reused with a mutated payload.
function requestCanonicalSha256(req) {
  return sha256(
    canonicalJson({
      request_id: req.request_id,
      actor: req.actor,
      requested_capability: req.requested_capability,
      operation: req.operation,
      params: req.params,
      idempotency_key_sha256: sha256(req.idempotency_key),
      expected_sequence: req.expected_sequence,
      scope: req.scope,
      required_assurance: req.required_assurance,
    }),
  );
}

function stream(actor, capability) {
  return `${actor}::${capability}`;
}

// -----------------------------------------------------------------------------
// Result construction
// -----------------------------------------------------------------------------

function baseResult(ctx, req, bindingSha) {
  return {
    schema: SCHEMA,
    execution_id: ctx.execution_id,
    request_id: req ? req.request_id : null,
    idempotency_key_sha256: req ? sha256(req.idempotency_key) : null,
    actor: req ? req.actor : null,
    requested_capability: req ? req.requested_capability : null,
    operation: req ? req.operation : null,
    request_canonical_sha256: bindingSha || null,
    resolved_path: null,
    policy_hash: null,
    authorization_evidence: null,
    pre_state_hash: null,
    execution_timestamp: null,
    provider: null,
    provider_request_id: null,
    execution_result: null,
    verification_method: VERIFICATION_METHOD.NONE,
    verification_evidence: null,
    post_state_hash: null,
    assurance_level_achieved: ASSURANCE.L0,
    audit_entry_hash: null,
    canonical_commit_status: CANONICAL_COMMIT_STATUS.NOT_COMMITTED,
    stage_reached: 'REQUEST',
    state: null,
    detail: null,
    evidence_complete: false,
    observed_at: new Date(ctx.now).toISOString(),
  };
}

function terminal(result, state, stage, detail, patch = {}) {
  return Object.freeze({
    ...result,
    ...patch,
    state,
    stage_reached: stage,
    detail: detail || null,
    evidence_complete: state === RESULT_STATE.VERIFIED_SUCCESS,
  });
}

// -----------------------------------------------------------------------------
// Context assembly
// -----------------------------------------------------------------------------

function buildContext(context = {}) {
  const env = context.env || process.env;
  const stateDir = path.resolve(context.stateDir || '.secrets/g-verified-execution-spine');
  return {
    env,
    now: Number.isFinite(context.now) ? context.now : Date.now(),
    execution_id: context.execution_id || crypto.randomUUID(),
    registry: context.registry,
    policy: context.policy,
    authorizationEnvKey: context.authorizationEnvKey || 'G_SPINE_AUTHORIZATION_SECRET',
    idempotency:
      context.idempotency || new IdempotencyStore(path.join(stateDir, 'idempotency')),
    sequence: context.sequence || new SequenceStore(path.join(stateDir, 'sequence')),
    ledger: context.ledger || new ReceiptLedger(path.join(stateDir, 'audit.jsonl')),
    // Set true only where the caller has independently confirmed live external
    // effects are authorized for this process. Connectors may additionally gate.
    allowExternalEffects: context.allowExternalEffects === true,
  };
}

function appendAudit(ctx, event) {
  // Audit failure is fail-closed: the caller must treat a throw here as
  // INTERNAL_FAIL_CLOSED and must NOT report success.
  return ctx.ledger.append(safeEvidence(event));
}

// -----------------------------------------------------------------------------
// The canonical enforcement path
// -----------------------------------------------------------------------------

async function executeVerified(rawRequest, context = {}) {
  const ctx = buildContext(context);
  let result = baseResult(ctx, null, null);

  try {
    if (!ctx.registry) return terminal(result, RESULT_STATE.INTERNAL_FAIL_CLOSED, 'REQUEST', 'registry_missing');
    if (!ctx.policy) return terminal(result, RESULT_STATE.INTERNAL_FAIL_CLOSED, 'REQUEST', 'policy_missing');

    // ---- Stage REQUEST ------------------------------------------------------
    let req;
    try {
      req = normalizeRequest(rawRequest);
    } catch (err) {
      return terminal(result, RESULT_STATE.INTERNAL_FAIL_CLOSED, 'REQUEST', `malformed_request:${err.message}`);
    }
    const bindingSha = requestCanonicalSha256(req);
    result = baseResult(ctx, req, bindingSha);

    // ---- Stage VERIFY_SCOPE ----------------------------------------------- --
    const scopeBounded =
      Number.isSafeInteger(req.scope.max_effects) &&
      req.scope.max_effects >= 1 &&
      req.scope.max_effects <= 1; // the spine authorizes exactly one effect per call
    if (!scopeBounded) {
      return terminal(result, RESULT_STATE.DENIED_SCOPE, 'VERIFY_SCOPE', 'scope_must_bound_exactly_one_effect');
    }

    // ---- Stage CHECK_PATH -------------------------------------------------- --
    let connector;
    try {
      connector = ctx.registry.resolve(req.requested_capability);
    } catch (err) {
      return terminal(result, RESULT_STATE.NO_VERIFIED_PATH, 'CHECK_PATH', err.message);
    }
    result = { ...result, resolved_path: connector.name, provider: connector.name };

    // ---- Stage DISCOVER_CAPABILITY -------------------------------------- ----
    let discovery;
    try {
      discovery = await connector.discover({
        execution_id: ctx.execution_id,
        operation: req.operation,
        allowExternalEffects: ctx.allowExternalEffects,
        env: ctx.env,
      });
    } catch (err) {
      return terminal(result, RESULT_STATE.NO_VERIFIED_PATH, 'DISCOVER_CAPABILITY', `discover_failed:${err.message}`);
    }
    if (!discovery || discovery.ok !== true) {
      return terminal(result, RESULT_STATE.NO_VERIFIED_PATH, 'DISCOVER_CAPABILITY', 'capability_not_available');
    }
    const observedAssurance = String(discovery.observed_assurance || ASSURANCE.L0);
    if (!assuranceAtLeast(observedAssurance, req.required_assurance)) {
      return terminal(result, RESULT_STATE.NO_VERIFIED_PATH, 'DISCOVER_CAPABILITY',
        `assurance_below_required:${observedAssurance}<${req.required_assurance}`);
    }
    // The connector cannot claim more than its declared ceiling.
    const discoverAssurance = minAssurance(observedAssurance, connector.assurance_ceiling);

    // ---- Stage POLICY_CHECK --------------------------------------------- ----
    const policyDecision = ctx.policy.evaluate({
      actor: req.actor,
      capability: req.requested_capability,
      operation: req.operation,
      observed_assurance: discoverAssurance,
      amount_minor: req.scope.amount_minor,
      scope_bounded: scopeBounded,
    });
    result = { ...result, policy_hash: policyDecision.policy_hash };
    if (policyDecision.decision !== 'ALLOW') {
      return terminal(result, RESULT_STATE.DENIED_POLICY, 'POLICY_CHECK', policyDecision.reason, {
        verification_evidence: safeEvidence({ policy: policyDecision }),
      });
    }

    // ---- Stage AUTHORIZATION ------------------------------------------- -----
    let authz;
    try {
      authz = verifyAuthorization(
        rawRequest.authorization_token,
        {
          requestCanonicalSha256: bindingSha,
          idempotencyKey: req.idempotency_key,
          actor: req.actor,
          capability: req.requested_capability,
          operation: req.operation,
          now: ctx.now,
        },
        ctx.env,
        ctx.authorizationEnvKey,
      );
    } catch (err) {
      return terminal(result, RESULT_STATE.DENIED_AUTHORIZATION, 'AUTHORIZATION', err.message);
    }
    result = {
      ...result,
      authorization_evidence: safeEvidence({
        authorization_id: authz.authorization_id,
        request_canonical_sha256: authz.request_canonical_sha256,
        idempotency_key_sha256: authz.idempotency_key_sha256,
        actor: authz.actor,
        capability: authz.capability,
        operation: authz.operation,
        issued_at: authz.issued_at,
        expires_at: authz.expires_at,
        hmac_verified: true,
      }),
    };

    // ---- Idempotency + monotonic sequence pre-checks --------------------- --
    const idemRequest = {
      schema: 'g-verified-execution-idem-request/v1',
      binding_sha256: bindingSha,
      capability: req.requested_capability,
      operation: req.operation,
      actor: req.actor,
      authorization_id: authz.authorization_id,
    };
    const idemRequestSha = sha256(canonicalJson(idemRequest));

    const existing = ctx.idempotency.read(req.idempotency_key);
    if (existing) {
      if (existing.request_sha256 !== idemRequestSha) {
        return terminal(result, RESULT_STATE.REPLAY_REJECTED, 'AUTHORIZATION',
          'idempotency_key_reused_for_different_request');
      }
      if (existing.state === 'SUCCEEDED' && existing.result) {
        // Safe replay: return the recorded verified result, no re-execution.
        return Object.freeze({ ...existing.result, replayed: true });
      }
      // PENDING / UNKNOWN_REQUIRES_RECONCILIATION / FAILED_FINAL: the external
      // effect may have happened. Do not re-run; require reconcile().
      return terminal(result, RESULT_STATE.REPLAY_REJECTED, 'AUTHORIZATION',
        `idempotency_record_not_replayable_in_state_${existing.state}`, {
          canonical_commit_status: CANONICAL_COMMIT_STATUS.QUARANTINED_RECONCILE,
        });
    }

    const seqCheck = ctx.sequence.check(stream(req.actor, req.requested_capability), req.expected_sequence);
    if (!seqCheck.ok) {
      return terminal(result, RESULT_STATE.STALE_STATE_REJECTED, 'AUTHORIZATION',
        `${seqCheck.reason}:expected>${seqCheck.current}`);
    }

    // ---- Claim (atomic). A lost race here means someone else owns it. ------
    let claim;
    try {
      claim = ctx.idempotency.claim({ key: req.idempotency_key, request: idemRequest });
    } catch (err) {
      return terminal(result, RESULT_STATE.REPLAY_REJECTED, 'AUTHORIZATION', `claim_failed:${err.message}`);
    }
    if (!claim.owner) {
      return terminal(result, RESULT_STATE.REPLAY_REJECTED, 'AUTHORIZATION',
        `concurrent_execution_in_state_${claim.record.state}`);
    }

    // ---- pre-state + AUTHORIZED audit ------------------------------------- --
    let preStateHash;
    try {
      preStateHash = String(await connector.captureState({ operation: req.operation, params: req.params }));
    } catch (err) {
      await quarantine(ctx, req, idemRequest, `pre_state_capture_failed:${err.message}`);
      return terminal(result, RESULT_STATE.INTERNAL_FAIL_CLOSED, 'DISCOVER_CAPABILITY',
        `pre_state_capture_failed:${err.message}`);
    }
    result = { ...result, pre_state_hash: preStateHash };

    try {
      appendAudit(ctx, {
        event: 'EXECUTION_AUTHORIZED',
        execution_id: ctx.execution_id,
        request_id: req.request_id,
        actor: req.actor,
        capability: req.requested_capability,
        operation: req.operation,
        binding_sha256: bindingSha,
        policy_hash: policyDecision.policy_hash,
        authorization_id: authz.authorization_id,
        pre_state_hash: preStateHash,
        observed_assurance: discoverAssurance,
        params: safeEvidence(req.params),
        payment_created: false,
        value_moved: false,
      });
    } catch (err) {
      await quarantine(ctx, req, idemRequest, `audit_authorized_failed:${err.message}`);
      return terminal(result, RESULT_STATE.INTERNAL_FAIL_CLOSED, 'AUDIT', `audit_failure_fail_closed:${err.message}`);
    }

    // ---- Stage EXECUTE ------------------------------------------------- -----
    const execTs = new Date().toISOString();
    result = { ...result, execution_timestamp: execTs };
    let exec;
    try {
      exec = await connector.execute({
        execution_id: ctx.execution_id,
        request_id: req.request_id,
        actor: req.actor,
        operation: req.operation,
        params: req.params,
        idempotency_key: req.idempotency_key,
        scope: req.scope,
        binding_sha256: bindingSha,
        allowExternalEffects: ctx.allowExternalEffects,
        env: ctx.env,
      });
    } catch (err) {
      const definiteProviderFailure = Number.isInteger(err.provider_http_status);
      const finalState = definiteProviderFailure ? 'FAILED_FINAL' : 'UNKNOWN_REQUIRES_RECONCILIATION';
      safeFinalize(ctx, req, idemRequest, finalState, {
        error: err.message,
        provider_http_status: err.provider_http_status || null,
        // Hints for reconcile(): never re-issue, only re-observe.
        reconcile_params: definiteProviderFailure ? null : safeEvidence(req.params),
      });
      tryAudit(ctx, {
        event: definiteProviderFailure ? 'EXECUTION_PROVIDER_FAILURE' : 'EXECUTION_UNCONFIRMED',
        execution_id: ctx.execution_id,
        request_id: req.request_id,
        provider: connector.name,
        provider_http_status: err.provider_http_status || null,
        state: finalState,
        payment_created: false,
        value_moved: false,
      });
      return terminal(
        result,
        definiteProviderFailure ? RESULT_STATE.PROVIDER_FAILURE : RESULT_STATE.EXECUTION_UNVERIFIED,
        'EXECUTE',
        err.message,
        { canonical_commit_status: CANONICAL_COMMIT_STATUS.QUARANTINED_RECONCILE },
      );
    }

    if (!exec || exec.provider_request_id == null || String(exec.provider_request_id).length === 0) {
      safeFinalize(ctx, req, idemRequest, 'UNKNOWN_REQUIRES_RECONCILIATION', {
        error: 'provider_receipt_missing_request_id',
      });
      tryAudit(ctx, {
        event: 'EXECUTION_UNCONFIRMED',
        execution_id: ctx.execution_id,
        request_id: req.request_id,
        provider: connector.name,
        state: 'UNKNOWN_REQUIRES_RECONCILIATION',
        detail: 'provider_receipt_missing_request_id',
      });
      return terminal(result, RESULT_STATE.EXECUTION_UNVERIFIED, 'EXECUTE',
        'provider_receipt_missing_request_id',
        { canonical_commit_status: CANONICAL_COMMIT_STATUS.QUARANTINED_RECONCILE });
    }
    result = {
      ...result,
      provider_request_id: String(exec.provider_request_id),
      execution_result: safeEvidence({
        applied_claim: exec.applied === true,
        raw_status: exec.raw_status || null,
        receipt: exec.receipt || null,
      }),
    };

    // ---- Stage VERIFY_READBACK --------------------------------------- -------
    // Discovery assurance was the *entry gate*. What THIS execution+verification
    // proves is bounded only by the connector's declared ceiling, not by the
    // read-only discovery level.
    const ceiling = connector.assurance_ceiling;
    let verificationMethod = VERIFICATION_METHOD.PROVIDER_RECEIPT_ONLY;
    let achievedAssurance = minAssurance(ceiling, ASSURANCE.L3);
    let verificationEvidence = { mode: 'provider_receipt_only', provider_request_id: String(exec.provider_request_id) };

    if (connector.supportsReadback) {
      let readback;
      try {
        readback = await connector.readback(
          { operation: req.operation, params: req.params, binding_sha256: bindingSha },
          exec,
        );
      } catch (err) {
        safeFinalize(ctx, req, idemRequest, 'UNKNOWN_REQUIRES_RECONCILIATION', {
          error: `readback_failed:${err.message}`,
          provider_request_id: String(exec.provider_request_id),
        });
        tryAudit(ctx, {
          event: 'EXECUTION_READBACK_UNCERTAIN',
          execution_id: ctx.execution_id,
          request_id: req.request_id,
          provider: connector.name,
          provider_request_id: String(exec.provider_request_id),
          state: 'UNKNOWN_REQUIRES_RECONCILIATION',
        });
        return terminal(result, RESULT_STATE.EXECUTION_UNVERIFIED, 'VERIFY_READBACK',
          `readback_failed:${err.message}`,
          { canonical_commit_status: CANONICAL_COMMIT_STATUS.QUARANTINED_RECONCILE });
      }

      if (!readback || readback.verified !== true || readback.binding_ok !== true) {
        // Provider/connector may say "ok" but verification does not confirm it.
        safeFinalize(ctx, req, idemRequest, 'UNKNOWN_REQUIRES_RECONCILIATION', {
          error: 'readback_did_not_confirm_effect',
          provider_request_id: String(exec.provider_request_id),
          observed_status: readback ? readback.observed_status || null : null,
        });
        tryAudit(ctx, {
          event: 'EXECUTION_READBACK_MISMATCH',
          execution_id: ctx.execution_id,
          request_id: req.request_id,
          provider: connector.name,
          provider_request_id: String(exec.provider_request_id),
          observed_status: readback ? readback.observed_status || null : null,
        });
        return terminal(result, RESULT_STATE.READBACK_MISMATCH, 'VERIFY_READBACK',
          'readback_did_not_confirm_effect', {
            verification_evidence: safeEvidence({ readback: readback || null }),
            canonical_commit_status: CANONICAL_COMMIT_STATUS.QUARANTINED_RECONCILE,
          });
      }

      // L4 is only awarded for an external readback whose binding evidence is
      // STRONG (payment id + amount + currency + intent/reference hash +
      // counterparty binding, all present and matched). An external readback
      // with WEAK binding is honestly capped at L3 / PROVIDER_RECEIPT_ONLY —
      // it proves an object exists, not that it is *this* execution's effect.
      const strongBinding = readback.binding_strength === 'STRONG';
      if (readback.external === true && strongBinding) {
        verificationMethod = VERIFICATION_METHOD.AUTHENTICATED_PROVIDER_READBACK;
        achievedAssurance = minAssurance(ceiling, ASSURANCE.L4);
      } else if (readback.external === true) {
        verificationMethod = VERIFICATION_METHOD.PROVIDER_RECEIPT_ONLY;
        achievedAssurance = minAssurance(ceiling, ASSURANCE.L3);
      } else {
        verificationMethod = VERIFICATION_METHOD.LOCAL_STATE_READBACK;
        achievedAssurance = minAssurance(ceiling, ASSURANCE.L1);
      }
      verificationEvidence = {
        mode: 'readback',
        observed_status: readback.observed_status || null,
        external: readback.external === true,
        binding_strength: readback.binding_strength || (readback.external === true ? 'WEAK' : 'LOCAL'),
      };
    } else {
      // No readback available. Classify honestly: strongest external receipt
      // only, capped at L3, never "fully verified".
      achievedAssurance = minAssurance(ceiling, ASSURANCE.L3);
    }

    // ---- post-state ------------------------------------------------------- --
    let postStateHash;
    try {
      postStateHash = String(await connector.captureState({ operation: req.operation, params: req.params }));
    } catch (err) {
      safeFinalize(ctx, req, idemRequest, 'UNKNOWN_REQUIRES_RECONCILIATION', {
        error: `post_state_capture_failed:${err.message}`,
        provider_request_id: String(exec.provider_request_id),
      });
      return terminal(result, RESULT_STATE.EXECUTION_UNVERIFIED, 'VERIFY_READBACK',
        `post_state_capture_failed:${err.message}`,
        { canonical_commit_status: CANONICAL_COMMIT_STATUS.QUARANTINED_RECONCILE });
    }

    // ---- Stage RECEIPT ------------------------------------------------- -----
    const receiptResult = {
      ...result,
      verification_method: verificationMethod,
      verification_evidence: safeEvidence(verificationEvidence),
      post_state_hash: postStateHash,
      assurance_level_achieved: achievedAssurance,
      state: RESULT_STATE.VERIFIED_SUCCESS,
      stage_reached: 'RECEIPT',
      evidence_complete: true,
    };
    receiptResult.result_sha256 = sha256(canonicalJson(stripVolatile(receiptResult)));

    // ---- Stage AUDIT (fail-closed) ----------------------------------- ------
    let auditRow;
    try {
      auditRow = appendAudit(ctx, {
        event: 'VERIFIED_EXECUTION_COMMIT',
        execution_id: ctx.execution_id,
        request_id: req.request_id,
        actor: req.actor,
        capability: req.requested_capability,
        operation: req.operation,
        provider: connector.name,
        provider_request_id: String(exec.provider_request_id),
        binding_sha256: bindingSha,
        policy_hash: policyDecision.policy_hash,
        authorization_id: authz.authorization_id,
        pre_state_hash: preStateHash,
        post_state_hash: postStateHash,
        verification_method: verificationMethod,
        assurance_level_achieved: achievedAssurance,
        result_sha256: receiptResult.result_sha256,
        expected_sequence: req.expected_sequence,
      });
    } catch (err) {
      // The effect happened but we cannot write tamper-evident audit. Never
      // report success. Quarantine for reconciliation.
      safeFinalize(ctx, req, idemRequest, 'UNKNOWN_REQUIRES_RECONCILIATION', {
        error: `audit_commit_failed:${err.message}`,
        provider_request_id: String(exec.provider_request_id),
      });
      return terminal(result, RESULT_STATE.INTERNAL_FAIL_CLOSED, 'AUDIT',
        `audit_failure_fail_closed:${err.message}`,
        { canonical_commit_status: CANONICAL_COMMIT_STATUS.QUARANTINED_RECONCILE });
    }

    // ---- Stage COMMIT_STATE ------------------------------------------ ------
    const committed = Object.freeze({
      ...receiptResult,
      audit_entry_hash: auditRow.record_sha256,
      canonical_commit_status: CANONICAL_COMMIT_STATUS.COMMITTED,
      stage_reached: 'COMMIT_STATE',
    });

    try {
      ctx.idempotency.finalize({
        key: req.idempotency_key,
        request: idemRequest,
        state: 'SUCCEEDED',
        result: committed,
      });
      ctx.sequence.commit(stream(req.actor, req.requested_capability), req.expected_sequence);
    } catch (err) {
      // Audit already recorded the commit; local bookkeeping failed. Report
      // fail-closed so the caller reconciles rather than trusting an
      // un-finalized record.
      return terminal(result, RESULT_STATE.INTERNAL_FAIL_CLOSED, 'COMMIT_STATE',
        `local_commit_bookkeeping_failed:${err.message}`,
        { audit_entry_hash: auditRow.record_sha256,
          canonical_commit_status: CANONICAL_COMMIT_STATUS.QUARANTINED_RECONCILE });
    }

    return committed;
  } catch (err) {
    // Any unforeseen error is a fail-closed internal failure, never a success.
    return terminal(result, RESULT_STATE.INTERNAL_FAIL_CLOSED, result.stage_reached || 'REQUEST',
      `unhandled:${err && err.message ? err.message : String(err)}`);
  }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

function stripVolatile(r) {
  const { observed_at, result_sha256, audit_entry_hash, ...rest } = r;
  return rest;
}

function safeFinalize(ctx, req, idemRequest, state, resultObj) {
  try {
    ctx.idempotency.finalize({
      key: req.idempotency_key,
      request: idemRequest,
      state,
      result: safeEvidence({
        capability: req.requested_capability,
        operation: req.operation,
        idempotency_key_sha256: sha256(req.idempotency_key),
        // Non-sensitive canonical request hash — lets reconcile() re-bind the
        // provider effect to this exact request without any redacted params.
        binding_sha256: idemRequest && idemRequest.binding_sha256 ? idemRequest.binding_sha256 : null,
        ...resultObj,
      }),
    });
  } catch {
    /* best effort; caller already returns a fail-closed state */
  }
}

async function quarantine(ctx, req, idemRequest, reason) {
  safeFinalize(ctx, req, idemRequest, 'UNKNOWN_REQUIRES_RECONCILIATION', { error: reason });
}

function tryAudit(ctx, event) {
  try {
    appendAudit(ctx, event);
  } catch {
    /* audit best-effort on already-failing paths */
  }
}

// -----------------------------------------------------------------------------
// Recovery: reconcile a quarantined idempotency record BEFORE any retry.
// -----------------------------------------------------------------------------
//
// Handles the hard case: the provider may have executed, but the local process
// died before COMMIT_STATE. We ask the connector to prove — via readback — what
// actually happened, then finalize the record. We NEVER re-issue the external
// effect here.
async function reconcile({ idempotency_key, provider_request_id }, context = {}) {
  const ctx = buildContext(context);
  if (!ctx.registry) throw new Error('registry_missing');
  const record = ctx.idempotency.read(idempotency_key);
  if (!record) {
    return { reconciled: false, state: 'NO_RECORD', detail: 'no idempotency record for key' };
  }
  if (record.state === 'SUCCEEDED') {
    return { reconciled: true, state: 'ALREADY_COMMITTED', result: record.result };
  }
  if (record.state === 'FAILED_FINAL') {
    return { reconciled: true, state: 'CONFIRMED_FAILED', detail: record.result };
  }

  const capability = record.result && record.result.capability;
  // The stored idem request carries capability; fall back to explicit context.
  const capName = capability || context.capability;
  if (!capName) {
    return { reconciled: false, state: 'INDETERMINATE', detail: 'capability unknown for reconcile' };
  }
  let connector;
  try {
    connector = ctx.registry.resolve(capName);
  } catch (err) {
    return { reconciled: false, state: 'INDETERMINATE', detail: err.message };
  }
  if (!connector.supportsReadback) {
    return {
      reconciled: false,
      state: 'MANUAL_REQUIRED',
      detail: 'connector has no readback; external evidence must be reviewed by an operator',
    };
  }

  let readback;
  try {
    readback = await connector.readback(
      {
        operation: 'reconcile',
        reconcile: true,
        params: { ...((record.result && record.result.reconcile_params) || {}), reconcile: true },
        binding_sha256: (record.result && record.result.binding_sha256) || null,
      },
      { provider_request_id, idempotency_key_sha256: sha256(String(idempotency_key)) },
    );
  } catch (err) {
    return { reconciled: false, state: 'STILL_UNCERTAIN', detail: `readback_failed:${err.message}` };
  }

  // Confirmed: the connector read back the effect AND bound it to this
  // execution. Recover the original outcome; never re-issue.
  if (readback && readback.verified === true && readback.binding_ok !== false) {
    appendAudit(ctx, {
      event: 'RECONCILED_EFFECT_CONFIRMED',
      idempotency_key_sha256: sha256(String(idempotency_key)),
      provider: connector.name,
      provider_request_id: provider_request_id || readback.provider_request_id || null,
      observed_status: readback.observed_status || null,
    });
    return { reconciled: true, state: 'EFFECT_CONFIRMED', readback: safeEvidence(readback) };
  }

  // The connector reached the provider and it is definitively NOT there.
  const status = String((readback && readback.observed_status) || '').toUpperCase();
  const definitivelyAbsent = ['NOT_FOUND', 'ABSENT'].includes(status);
  if (readback && readback.verified === false && definitivelyAbsent) {
    appendAudit(ctx, {
      event: 'RECONCILED_EFFECT_ABSENT',
      idempotency_key_sha256: sha256(String(idempotency_key)),
      provider: connector.name,
      provider_request_id: provider_request_id || null,
    });
    return {
      reconciled: true,
      state: 'EFFECT_ABSENT',
      detail: 'no external effect found; a fresh request may be issued after an explicit safe state transition',
    };
  }

  // Could not determine (no correlation id, provider unreachable, binding
  // mismatch). Do NOT allow a retry — an operator must resolve it.
  const manual = readback && (readback.manual_required === true || readback.binding_ok === false);
  appendAudit(ctx, {
    event: 'RECONCILE_UNRESOLVED',
    idempotency_key_sha256: sha256(String(idempotency_key)),
    provider: connector.name,
    observed_status: (readback && readback.observed_status) || null,
    outcome: manual ? 'MANUAL_REQUIRED' : 'STILL_UNCERTAIN',
  });
  return {
    reconciled: false,
    state: manual ? 'MANUAL_REQUIRED' : 'STILL_UNCERTAIN',
    detail: 'reconcile could not prove presence or absence of the external effect; retry is not permitted',
  };
}

module.exports = {
  SCHEMA,
  executeVerified,
  reconcile,
  normalizeRequest,
  requestCanonicalSha256,
  buildContext,
};
