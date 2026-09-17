# ATLAS Revolut Payment Path v2

## Purpose
Use the user's existing Revolut payment account as the primary manual-SCA bank path without requiring a Revolut Business API subscription.

## Paths
- `revolut-manual-sca`: primary current path. ATLAS may verify evidence and prepare a local instruction; only the user may approve the transfer in Revolut.
- `revolut-open-banking`: automation target. Requires a verified PISP transport plus verified Revolut payment-initiation route.
- `bunq-native-draft`: remains supported generically but may be marked `NOT_APPLICABLE` in user runtime configuration.

## Evidence boundary
Historical account statements prove only historical account evidence. They do not prove current account status, available balance, single-transfer limit, beneficiary verification, SCA readiness, or transaction authorization.

A current activation proof must be fresh, rail-bound, source-referenced, and SHA-256 bound to its canonical payload.

## High-value boundary
For EUR 294,900, ATLAS must still require fresh dealer invoice/VIN/IBAN, beneficiary verification, a verified bank single-payment limit covering the full amount, SCA, and fresh exact owner authorization.

No split-payment workaround is permitted. Provider/bank execution is not equivalent to creditor settlement.
