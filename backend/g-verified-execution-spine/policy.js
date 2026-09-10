'use strict';

const { canonicalJson, sha256 } = require('../g-bank-live-v1/canonical');
const { ASSURANCE_RANK } = require('./states');

// Deterministic, default-deny policy engine.
//
// Evaluation contract ("strictest applicable policy wins"):
//   * The baseline decision is DENY.
//   * A rule applies when every constraint in its `match` block is satisfied.
//   * ANY applicable DENY rule is decisive: the result is DENY, regardless of
//     rule order or priority. Deny always beats allow.
//   * The result is ALLOW only if at least one ALLOW rule applies AND no DENY
//     rule applies.
//   * An unknown/!= actor, capability or operation never matches a wildcard it
//     was not explicitly granted.
//
// A ruleset is an ordered array; `policy_hash` is sha256 over its canonical
// form so a tampered or swapped ruleset is detectable in the receipt.

function normalizeRule(rule, index) {
  if (!rule || typeof rule !== 'object') {
    throw new Error(`policy_rule_invalid_at_${index}`);
  }
  if (rule.effect !== 'ALLOW' && rule.effect !== 'DENY') {
    throw new Error(`policy_rule_effect_invalid_at_${index}`);
  }
  const match = rule.match && typeof rule.match === 'object' ? rule.match : {};
  return {
    id: String(rule.id || `rule-${index}`),
    effect: rule.effect,
    match: {
      actor: match.actor === undefined ? null : String(match.actor),
      capability: match.capability === undefined ? null : String(match.capability),
      operation: match.operation === undefined ? null : String(match.operation),
      min_assurance: match.min_assurance === undefined ? null : String(match.min_assurance),
      max_amount_minor:
        match.max_amount_minor === undefined || match.max_amount_minor === null
          ? null
          : Number(match.max_amount_minor),
      require_scope_bounded: match.require_scope_bounded === true,
    },
  };
}

class PolicyEngine {
  constructor(rules) {
    if (!Array.isArray(rules)) throw new Error('policy_ruleset_must_be_array');
    this.rules = rules.map(normalizeRule);
    this.policy_hash = sha256(canonicalJson(this.rules));
  }

  // subject: { actor, capability, operation, observed_assurance, amount_minor?, scope_bounded }
  evaluate(subject) {
    const s = {
      actor: String(subject.actor || ''),
      capability: String(subject.capability || ''),
      operation: String(subject.operation || ''),
      observed_assurance: String(subject.observed_assurance || 'L0'),
      amount_minor:
        subject.amount_minor === undefined || subject.amount_minor === null
          ? null
          : Number(subject.amount_minor),
      scope_bounded: subject.scope_bounded === true,
    };

    const applies = (rule) => {
      const m = rule.match;
      if (m.actor !== null && m.actor !== s.actor) return false;
      if (m.capability !== null && m.capability !== s.capability) return false;
      if (m.operation !== null && m.operation !== s.operation) return false;
      if (m.require_scope_bounded && !s.scope_bounded) return false;
      if (
        m.min_assurance !== null &&
        (ASSURANCE_RANK[s.observed_assurance] ?? -1) <
          (ASSURANCE_RANK[m.min_assurance] ?? 99)
      ) {
        return false;
      }
      if (
        m.max_amount_minor !== null &&
        (s.amount_minor === null || s.amount_minor > m.max_amount_minor)
      ) {
        return false;
      }
      return true;
    };

    const matched = this.rules.filter(applies);
    const denies = matched.filter((r) => r.effect === 'DENY');
    const allows = matched.filter((r) => r.effect === 'ALLOW');

    let decision = 'DENY';
    let reason;
    if (denies.length > 0) {
      decision = 'DENY';
      reason = `explicit_deny:${denies.map((r) => r.id).join(',')}`;
    } else if (allows.length > 0) {
      decision = 'ALLOW';
      reason = `allowed_by:${allows.map((r) => r.id).join(',')}`;
    } else {
      decision = 'DENY';
      reason = 'default_deny_no_matching_allow';
    }

    return {
      decision,
      reason,
      policy_hash: this.policy_hash,
      matched_rule_ids: matched.map((r) => r.id),
      deny_rule_ids: denies.map((r) => r.id),
      allow_rule_ids: allows.map((r) => r.id),
    };
  }
}

module.exports = { PolicyEngine };
