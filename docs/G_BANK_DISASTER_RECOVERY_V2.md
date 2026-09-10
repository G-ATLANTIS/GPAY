# G-BANK Disaster Recovery v2

## Purpose

G-BANK Disaster Recovery v2 protects the software state required to verify and recover the sovereign banking core. It is a software integrity and availability mechanism. It does not create a banking licence, scheme participation, central-bank access, settlement rights, external signing authority, or permission to move value.

## Fail-closed recovery chain

```text
CANONICAL STATE
  -> CHECKPOINT ROOT
  -> SECRET-EXCLUDING RECOVERY MANIFEST
  -> ATOMIC VERIFIED SNAPSHOT
  -> APPEND-ONLY RECOVERY ANCHOR
  -> RESTORE VERIFICATION
  -> RECOVERY READINESS AUDIT
  -> SOVEREIGN READINESS
  -> SHORT-LIVED TECHNICAL PROMOTION
  -> RUNTIME PROMOTION REVERIFICATION
  -> EXTERNAL SETTLEMENT SUBMIT
```

Every transition is fail-closed. Missing, malformed, stale, tampered or mismatched evidence blocks promotion or submission.

## Recovery manifest

`recovery-manifest.js` binds an ordered set of state files/directories to a checkpoint root and generation.

Controls:

- SHA-256 binding for every file and canonical directory tree.
- Generation 1 must be genesis; later generations must bind the immediately previous manifest.
- Duplicate labels and overlapping source paths are rejected.
- Symlinks and unsupported filesystem entries are rejected.
- Secret-like paths are rejected both at the top level and recursively inside allowed directories. This includes credentials, tokens, passwords, API keys and private-key paths.
- Manifest boundaries explicitly state `contains_secret_material=false`, `grants_external_rights=false`, and `permits_value_movement=false`.

## Atomic snapshot

`recovery-snapshot.js` copies only manifest-approved state into an isolated generation directory.

Controls:

- Source hashes are verified before copy.
- The destination may not be nested inside a protected source tree.
- Every copied file is fsynced and the copied snapshot is hash-verified before atomic rename.
- Sources are re-verified after copy to detect mutation during snapshot creation.
- The final snapshot is verified again after rename.
- Reusing an existing generation is idempotent only when its manifest and all bytes still match.
- Partial temporary snapshots are removed on failure.

## Recovery anchor chain

`recovery-anchor-store.js` maintains an append-only anti-rollback chain.

Each anchor binds:

- monotonic generation;
- current manifest hash;
- previous manifest hash;
- checkpoint state root;
- evidence hash;
- previous anchor-record hash.

Every anchor record re-verifies its own hash and safety boundaries. Generation gaps or disconnected manifest history are rejected.

## Restore verification

`restore-verifier.js` does not activate a restored state. It verifies a candidate only.

A candidate must match:

- the manifest;
- the trusted anchor record;
- the checkpoint root;
- every restored file/directory hash and size.

Rollback to an older generation is denied. A forward restore may advance only one anchored generation at a time unless all intermediate anchors are independently verified. Restore verification explicitly reports `restored_secret_material=false`, `activates_live_execution=false`, and `permits_value_movement=false`.

## Recovery readiness audit

`recovery-readiness-audit.js` converts a verified snapshot into a short-lived operational evidence object. It requires:

- valid manifest;
- valid complete anchor chain;
- latest manifest/anchor generation match;
- exact checkpoint-root match;
- byte-perfect restore verification;
- freshness of manifest, anchor and checkpoint;
- no secret material;
- no live activation;
- no value movement.

The resulting `g-bank-recovery-readiness-audit/v2` is itself hash-bound.

## LIVE readiness binding

`readiness.js` requires a configured `G_BANK_RECOVERY_AUDIT_SHA256` and a valid `PASS` recovery audit. The audit hash must match the configured binding. The readiness snapshot records the exact recovery checkpoint state root and all non-secret evidence hashes used for readiness.

Therefore `DIRECT_LIVE_READY` is false when recovery evidence is missing, invalid, stale at audit creation, tampered, unsafe, or bound to a different configured hash.

## Technical promotion binding

`promotion-certificate.js` requires every readiness check to be true. A promotion certificate can be created only when:

- the exact readiness evidence bindings match the certificate bindings;
- the promotion checkpoint root equals the recovery checkpoint root in readiness;
- monitoring and recovery controls are verified;
- governance policy and authority-set hashes are bound.

The certificate is short-lived and explicitly states:

- `grants_external_rights=false`;
- `permits_value_movement_by_itself=false`;
- `requires_runtime_reverification=true`.

## Runtime submit gate

`runtime-promotion-gate.js` re-verifies the readiness file and promotion certificate immediately in the live runtime. It compares the certificate against active runtime bindings for legal authorization evidence, scheme participation, settlement access, production identity, prudential controls, resilience, treasury, customer monitoring and recovery.

The core publishes its normalized active policy hash and authority-set hash into the shared runtime context. The runtime gate requires those hashes to equal the promotion certificate governance bindings.

`direct-settlement.js` then requires:

- LIVE/external/direct-settlement flags;
- a fresh authenticated/connected settlement preflight from the same adapter instance;
- matching payment scheme;
- a valid runtime promotion gate;
- the independent configured promotion-certificate SHA-256 binding.

Only after those checks may `transport.submit()` be called.

Reconciliation/readback remains available for an already submitted ambiguous transaction even after the original promotion expires. This avoids turning an expired submit authorization into an inability to determine the state of funds already in flight.

## CLI sequence

The live CLI uses an explicit three-stage gate:

```text
readiness -> promote -> execute
```

### 1. Readiness

```bash
node scripts/g-bank-sovereign-v2.js readiness \
  --prudential <prudential.json> \
  --monitoring-audit <monitoring-audit.json> \
  --recovery-audit <recovery-audit.json> \
  --risk-policy <risk-policy.json> \
  --authority-set <authority-set.json> \
  --out <readiness.json>
```

This performs a live transport preflight but submits no payment and moves no value.

### 2. Promotion

```bash
node scripts/g-bank-sovereign-v2.js promote \
  --readiness <readiness.json> \
  --checkpoint <checkpoint.json> \
  --risk-policy <risk-policy.json> \
  --authority-set <authority-set.json> \
  --trusted-signing-key-binding-sha256 <64-hex-sha256> \
  --ttl-seconds 120 \
  --out <promotion.json>
```

Record the emitted `certificate_sha256` through an independent trusted configuration path. Do not derive or silently trust it inside `execute`.

### 3. Execute

```bash
node scripts/g-bank-sovereign-v2.js execute \
  --prepared <prepared.json> \
  --validation <validation.json> \
  --approval <approval.token> \
  --signatures <authority-signatures.json> \
  --idempotency-key <uuid> \
  --readiness <readiness.json> \
  --promotion <promotion.json> \
  --promotion-sha256 <independently-bound-64-hex-sha256> \
  --risk-policy <risk-policy.json> \
  --authority-set <authority-set.json>
```

The runtime gate is checked before execution and again at the external settlement submission boundary. A missing/expired/tampered/mismatched promotion prevents `transport.submit()`.

## Tested attacks and failure cases

The no-network sovereign safety suite covers:

- source mutation after manifest creation;
- nested secret/private-key files;
- symlinks;
- overlapping backup sources;
- snapshot destination inside protected source;
- snapshot byte tamper;
- recovery anchor record tamper;
- rollback to older generations;
- generation skips;
- stale recovery evidence;
- missing runtime promotion;
- promotion certificate tamper and expiry;
- promotion SHA mismatch;
- recovery evidence binding mismatch;
- active policy mismatch;
- active authority-set mismatch;
- symlinked runtime evidence files;
- no network submit when the runtime gate fails.

## Reality boundary

This recovery architecture protects software state and controls access to an authorized external settlement adapter. It does not prove that such an adapter, legal authorization, scheme membership, IBAN-issuance authority, T2/TIPS/CSM access or production signing infrastructure exists. Those capabilities remain external evidence requirements and fail closed when absent.
