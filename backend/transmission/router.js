'use strict';

const { TransportState } = require('./etherWeb');

class MultipathRouter {
  constructor({ web, scorer = null }) {
    if (!web) throw new Error('web is required');
    this.web = web;
    this.scorer = scorer || this.defaultScore;
  }

  defaultScore(metrics = {}) {
    const latency = Number.isFinite(metrics.latencyMs) ? metrics.latencyMs : 1000;
    const loss = Number.isFinite(metrics.lossPct) ? metrics.lossPct : 100;
    const cost = Number.isFinite(metrics.costScore) ? metrics.costScore : 50;
    const trust = Number.isFinite(metrics.trustScore) ? metrics.trustScore : 50;
    const availability = Number.isFinite(metrics.availabilityScore) ? metrics.availabilityScore : 0;
    return (trust * 3) + (availability * 3) - latency - (loss * 20) - cost;
  }

  candidates(metricMap = {}) {
    return [...this.web.adapters.values()]
      .filter((adapter) => adapter.enabled && adapter.state === TransportState.AUTHORIZED_ACTIVE)
      .map((adapter) => ({
        adapter,
        metrics: metricMap[adapter.id] || {},
        score: this.scorer(metricMap[adapter.id] || {}, adapter),
      }))
      .sort((a, b) => b.score - a.score);
  }

  async send({ payload, destination, metrics = {}, maxAttempts = Infinity }) {
    const candidates = this.candidates(metrics);
    if (!candidates.length) {
      const error = new Error('no authorized active transport is available');
      error.code = 'G_NO_ACTIVE_TRANSPORT';
      throw error;
    }

    const failures = [];
    let attempts = 0;
    for (const candidate of candidates) {
      if (attempts >= maxAttempts) break;
      attempts += 1;
      try {
        const result = await this.web.send({
          transportId: candidate.adapter.id,
          payload,
          destination,
        });
        return {
          ok: true,
          transportId: candidate.adapter.id,
          score: candidate.score,
          attempts,
          result,
          failures,
        };
      } catch (error) {
        failures.push({ transportId: candidate.adapter.id, code: error.code || null, message: error.message });
      }
    }

    const error = new Error('all authorized active transports failed');
    error.code = 'G_ALL_ACTIVE_TRANSPORTS_FAILED';
    error.failures = failures;
    throw error;
  }
}

module.exports = { MultipathRouter };
