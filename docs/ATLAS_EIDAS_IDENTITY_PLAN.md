# ATLAS eIDAS PISP Identity Plan

Status: PREPARED / CERTIFICATES NOT ISSUED
Date: 2026-09-17

## Target identity
After DNB payment-service-7 authorisation, obtain and operate:
- QWAC for transport/authentication;
- QSeal/QSEAL for signing where required by institution/API profile.

## Issuance boundary
Certificates must come from an appropriate EU Qualified Trust Service Provider (QTSP). ATLAS does not self-assert regulatory certificate validity.

## Key handling
- private keys generated/imported into HSM/KMS-grade signing boundary;
- private keys marked non-exportable;
- plaintext private keys in `.env`, repository, logs and evidence artifacts: DENY;
- certificate metadata, public certificate and SHA-256 fingerprints may be audited;
- signing operations return signatures, never private-key material.

## Rotation and expiry
- monitor not-before/not-after dates;
- renewal begins before operational expiry;
- old and new certificate bindings overlap only through explicit rotation state;
- expired or unbound certificates fail closed.

## Bank binding
Every institution registration records which PISP identity and certificate pair was used. Certificate rotation invalidates stale registration evidence until the bank binding is reverified.