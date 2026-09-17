# ATLAS DNB PISP Application Pack

Status: PREPARED / NOT SUBMITTED / EXTERNAL AUTHORISATION REQUIRED
Date: 2026-09-17
Scope: Dutch payment service 7 — payment initiation services.

## Regulatory boundary
ATLAS must not provide regulated third-party payment initiation under its own identity until DNB authorisation is granted. No exemption path is assumed.

## Submission channel
- DNB Supervisory Applications / Digital Supervision Portal.
- eHerkenning is required for portal access.
- Treat submission as a legal-entity action, not a software deployment.

## Application workstreams
1. Legal entity and corporate structure.
2. Defined payment-service-7 business model and programme of operations.
3. Governance and fit/proper management evidence.
4. Risk-management and internal-control framework.
5. ICT/security architecture and access controls.
6. Incident management and regulatory reporting.
7. Business continuity and disaster recovery.
8. Outsourcing/vendor-management framework.
9. Professional indemnity insurance or comparable guarantee.
10. Financial forecasts/capital planning.
11. Data protection, record retention and auditability.
12. Operational procedures for consent, SCA, fraud and complaints.
## Evidence already available from ATLAS
- immutable payment-intent binding;
- explicit owner consent receipt;
- provider-neutral routing and fail-closed execution gates;
- beneficiary/invoice/amount binding;
- SCA boundary: no bank credentials or OTP storage;
- idempotency and replay controls;
- provider status/readback and webhook verification;
- creditor settlement separated from provider execution;
- tamper-detecting proof chain;
- high-value policy and anti-splitting rule.

## External evidence still required
- legal entity identity and organisational chart;
- directors/policymakers and fit/proper information;
- eHerkenning access;
- PII/guarantee evidence;
- audited/approved financial projections and capital evidence;
- formal policies approved by management;
- DNB application receipt and completeness decision;
- final DNB authorisation for payment service 7.

## Current gate
`ATLAS_OWN_PISP_EXECUTION_READY = false`

This remains false until DNB authorisation and the eIDAS identity layer are independently verified.
