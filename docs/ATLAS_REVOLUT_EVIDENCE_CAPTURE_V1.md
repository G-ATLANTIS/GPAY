# ATLAS Revolut Evidence Capture v1

Purpose: convert fresh, explicit Revolut evidence into short-lived, cryptographically bound readiness facts without granting payment authority.

Evidence classes are independent: CURRENT_ACCOUNT, AVAILABLE_FUNDS, SINGLE_PAYMENT_LIMIT, and SCA_PATH. Each receipt is bound to `revolut-manual-sca`, provider `REVOLUT`, a source reference, observed/expiry timestamps and a SHA-256 over the canonical payload.

Historical statements may prove that an account existed at the statement date, but cannot satisfy fresh current-account, available-funds, high-value limit, or SCA evidence.

A successful evidence set may satisfy internal release gates, but `payment_endpoint_call_permitted=false` and `value_moved=false` remain invariant. Final entry and approval occur in the user's Revolut app.
