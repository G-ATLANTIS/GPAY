# G-BANK Continuous Monitoring v2

## Purpose

This layer adds continuous, evidence-bound customer and transaction monitoring to G-BANK Sovereign Core v2 without turning software risk signals into legal or regulatory determinations.

The monitoring system can fail closed inside G-BANK by suspending a customer relationship and linked internal accounts. It cannot by itself file an external report, declare a person legally suspicious, create regulatory authority, submit a payment, or move value.

## Canonical flow

```text
ACTIVE MONITORING POLICY EPOCH
        |
VERIFIED CUSTOMER MONITORING EVIDENCE
  - KYC refresh
  - sanctions rescreen
  - PEP rescreen
        |
EVIDENCE REVOCATION CHECK
        |
VERIFIED G-BANK LEDGER + LINKED CUSTOMER ACCOUNTS
        |
LEDGER-DERIVED TRANSACTION ACTIVITY SOURCE ROOT
        |
DETERMINISTIC TRANSACTION ASSESSMENT
        |
OPEN CASES + CASE SLA
        |
CONTINUOUS CUSTOMER ASSESSMENT
        |
CLEAR / REVIEW_REQUIRED / SUSPEND_REQUIRED
        |
OPTIONAL FAIL-CLOSED INTERNAL ENFORCEMENT
        |
POST-ENFORCEMENT REASSESSMENT
        |
FLEET COVERAGE AUDIT
        |
READINESS + PROMOTION + EOD BINDING
```

## Evidence model

`monitoring-evidence.js` accepts recurring customer-control evidence only when it is hash-bound, subject-bound and sufficiently fresh under the active monitoring policy.

The current proof binds:

- KYC refresh evidence hash;
- sanctions rescreen evidence hash;
- PEP rescreen evidence hash;
- customer subject binding;
- verification time.

Evidence can be revoked through `EvidenceRevocationStore`. Revocations are append-only and hash-chained. A revoked evidence hash cannot satisfy a continuous monitoring assessment.

The monitoring evidence proof explicitly states:

```text
technical_gate_only = true
regulatory_determination_made = false
```

## Transaction monitoring source

Transaction-monitoring metrics are not accepted as an unbound source of truth in the end-to-end cycle.

`transaction-activity-source.js` derives customer activity from:

- the verified sovereign ledger;
- customer accounts linked by `metadata.customer_id`;
- a specified currency and time window;
- the current ledger head and record count.

The resulting source root binds the exact ledger state, account set and time window. A later ledger write changes the source root.

Derived metrics currently include:

- transaction count;
- total inbound amount;
- total outbound amount;
- maximum single transaction amount;
- distinct counterparty count;
- new counterparty count;
- rapid-sequence count;
- return/recall count.

## Deterministic risk states

`transaction-monitoring.js` returns only internal software-control states:

```text
CLEAR
REVIEW_REQUIRED
SUSPEND_REQUIRED
```

Thresholds are policy inputs. The assessment never states that a customer or transaction is legally suspicious and never submits an external report.

## Monitoring policy governance

`monitoring-policy.js` defines a canonical hash-bound policy including:

- monotonic policy epoch;
- effective time;
- KYC freshness period;
- screening freshness period;
- transaction review/suspension thresholds;
- review SLA by case severity.

`MonitoringPolicyStore` persists policy epochs append-only. It requires:

- contiguous epochs;
- stable policy identity;
- strictly increasing effective times;
- complete policy hash verification;
- exclusive writes;
- no silent historical mutation.

Future policy epochs may be staged but do not activate before their effective time.

The complete policy directory is also included in the canonical G-BANK checkpoint root.

## Case management and review SLA

`MonitoringCaseStore` is append-only and hash-chained. Cases use these internal workflow states:

```text
OPEN -> UNDER_REVIEW -> ESCALATED -> CLOSED
  \-----------------------------> CLOSED
```

Case severities are `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.

The original `opened_at` is immutable across transitions. This prevents a state transition from silently resetting the SLA clock.

`monitoring-case-sla.js` compares unresolved cases with the active policy epoch. An overdue HIGH or CRITICAL case can produce `SUSPEND_REQUIRED`; lower-severity overdue cases produce `REVIEW_REQUIRED`.

No case transition automatically creates an external filing.

## Fail-closed enforcement

`ContinuousCustomerMonitoringService` combines recurring evidence, revocation state, transaction assessment and case state.

When an assessment is `SUSPEND_REQUIRED` and the customer is ACTIVE, enforcement delegates to the existing G-BANK customer-control service. That service first suspends linked ACTIVE internal accounts and only then marks the customer SUSPENDED.

A later CLEAR snapshot never automatically reactivates a suspended relationship. Reactivation remains a separate explicit controlled operation.

An open CRITICAL case continues to hold the relationship fail closed until that case is explicitly handled; a new clean screening result does not silently erase the case.

## Monitoring cycle coordinator

`MonitoringCycleCoordinator` runs the complete internal cycle against one active policy epoch:

1. verify the append-only policy store;
2. resolve the currently effective policy;
3. verify the ledger;
4. derive transaction metrics for every monitorable customer;
5. verify recurring customer evidence;
6. produce customer assessment;
7. optionally enforce fail-closed internal controls;
8. re-assess after enforcement so customer-state hashes are current;
9. run a fleet-wide monitoring audit.

The resulting cycle proof binds:

- active policy hash and epoch;
- policy-store root;
- ledger head and record count;
- all final assessment hashes;
- all enforcement hashes;
- transaction source roots;
- fleet-audit hash.

The cycle proof always states:

```text
automatic_reactivation_performed = false
regulatory_determination_made = false
external_report_submitted = false
external_payment_action_performed = false
value_moved = false
```

## Fleet audit

`monitoring-fleet-audit.js` checks every ACTIVE or SUSPENDED customer.

A PASS requires, among other things:

- one current hash-valid assessment for each monitorable customer;
- matching customer record hash;
- matching policy hash and epoch;
- assessment freshness;
- no ACTIVE customer with an unenforced `SUSPEND_REQUIRED` result;
- no SUSPENDED customer with a linked ACTIVE customer account.

This audit is a hard input to `DIRECT_LIVE_READY` through `G_BANK_CUSTOMER_MONITORING_AUDIT_SHA256`.

## Promotion and EOD binding

The technical promotion certificate requires `customer_monitoring_verified=true` and binds the fleet-audit hash. The certificate still grants no external rights and cannot move value by itself.

The end-of-day close also requires a valid PASS monitoring fleet audit and binds:

- monitoring fleet audit hash;
- active monitoring policy hash and epoch;
- checkpoint monitoring policy root;
- monitoring case state root;
- evidence revocation state root.

A business date therefore cannot become `CLOSED` when continuous customer monitoring is incomplete or blocked.

## Reality boundary

```text
G_BANK_CONTINUOUS_MONITORING_SOFTWARE = IMPLEMENTED_V2
G_BANK_LEDGER_DERIVED_TRANSACTION_MONITORING = IMPLEMENTED
G_BANK_MONITORING_EVIDENCE_REVOCATION = IMPLEMENTED
G_BANK_MONITORING_CASE_MANAGEMENT = IMPLEMENTED
G_BANK_MONITORING_POLICY_EPOCHS = IMPLEMENTED
G_BANK_MONITORING_FLEET_AUDIT = IMPLEMENTED
G_BANK_FAIL_CLOSED_INTERNAL_SUSPENSION = IMPLEMENTED

G_BANK_REGULATORY_SUSPICION_DETERMINATION = NOT_AUTOMATED
G_BANK_EXTERNAL_REGULATORY_REPORTING = NOT_AUTOMATED
G_BANK_EXTERNAL_PAYMENT_ACTION_FROM_MONITORING = DENY
G_BANK_VALUE_MOVEMENT_FROM_MONITORING = DENY
```

Continuous monitoring is therefore a defensive internal control plane. It does not replace legally required governance, qualified human review, regulated service providers, competent authorities or any external authorization required for live payment services.
