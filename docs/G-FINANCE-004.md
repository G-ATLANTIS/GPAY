# G-FINANCE-004 — GPAY producer

This branch exposes a bounded, machine-readable G-Bank status contract and a sandbox-only write/readback evidence producer for the -G finance control plane.

## Runtime status

Authenticated operator route:

`GET /api/open-banking/g-finance-status`

The response schema is `g-finance-runtime/1.0`.

The status endpoint never promotes local configuration into external provider proof:

- authenticated: false
- write_verified: false
- value_transfer_verified: false
- verified_value_flow: false

When sandbox is selected, external_actions_enabled is false.

## Sandbox write/readback proof

Run:

`npm run proof:banking:g-finance-write`

This calls the existing official TrueLayer sandbox generator/router diagnostic. Evidence is written only after the diagnostic returns successfully.

Default evidence file:

`.secrets/evidence/g-finance-sandbox-write-readback.json`

The evidence records:

- TrueLayer sandbox payment UUID
- provider generator verified
- provider webhook router verified
- local GPAY webhook delivery verified
- signed webhook acceptance verified
- readback_match=true
- value_moved=false
- creditor_settlement_proven=false
- verified_value_flow=false
- canonical SHA-256

The command refuses:

- non-sandbox TrueLayer environments
- G_BANK_ENABLE_LIVE=true
- overwriting an existing evidence file unless --force is explicitly supplied

## Test

`npm run test:banking:g-finance`

No production transfer is enabled or attempted by this implementation.
