#!/usr/bin/env node
'use strict';

const PHASES = Object.freeze({
  A: 'SPONSOR_LICENCE_SPONSOR_CONNECTIVITY',
  B: 'OWN_LICENCE_EXTERNAL_CONNECTIVITY',
  C: 'OWN_LICENCE_TIER1_DIRECT_BANKS',
  D: 'OWN_LICENCE_MULTI_BANK_DIRECT_WITH_TSP_FALLBACK'
});

function evaluateMigration(input = {}) {
  const blockers = [];
  let phase = 'A';
  if (input.sponsor_approved !== true) blockers.push('SPONSOR_APPROVAL_REQUIRED');
  if (input.sponsor_production_verified !== true) blockers.push('SPONSOR_PRODUCTION_NOT_VERIFIED');

  if (input.own_pisp_authorised === true && input.eidas_ready === true) phase = 'B';
  if (phase === 'B' && Number(input.direct_bank_count || 0) >= 1 && input.direct_bank_execution_verified === true) phase = 'C';
  if (phase === 'C' && Number(input.direct_bank_count || 0) >= 3 && input.redundant_tsp_verified === true) phase = 'D';

  return {
    schema: 'atlas-open-banking-migration-v1',
    phase,
    phase_name: PHASES[phase],
    sponsor_required_for_current_phase: phase === 'A',
    own_pisp_required_for_current_phase: ['B','C','D'].includes(phase),
    blockers: phase === 'A' ? blockers : [],
    destructive_cutover_permitted: false,
    value_moved: false
  };
}

module.exports = { PHASES, evaluateMigration };
