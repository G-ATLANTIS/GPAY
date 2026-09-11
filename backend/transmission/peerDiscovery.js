'use strict';

class PeerRegistry {
  constructor({ now = () => Date.now(), ttlMs = 120000 } = {}) {
    this.now = now;
    this.ttlMs = ttlMs;
    this.peers = new Map();
  }

  observe({ peerId, transportId, address, metadata = {}, verified = false }) {
    if (!peerId || !transportId || !address) throw new Error('peerId, transportId and address are required');
    const record = {
      peerId,
      transportId,
      address,
      metadata,
      verified: Boolean(verified),
      seenAt: this.now(),
    };
    this.peers.set(`${transportId}:${peerId}`, record);
    return record;
  }

  active() {
    const cutoff = this.now() - this.ttlMs;
    return [...this.peers.values()].filter((peer) => peer.seenAt >= cutoff);
  }

  verifiedActive() {
    return this.active().filter((peer) => peer.verified);
  }

  expire() {
    const cutoff = this.now() - this.ttlMs;
    for (const [key, peer] of this.peers.entries()) {
      if (peer.seenAt < cutoff) this.peers.delete(key);
    }
  }
}

class AccountlessDiscovery {
  constructor({ registry = new PeerRegistry(), discoverers = [] } = {}) {
    this.registry = registry;
    this.discoverers = discoverers;
  }

  registerDiscoverer(discoverer) {
    if (!discoverer || typeof discoverer.scan !== 'function') {
      throw new TypeError('discoverer must expose scan()');
    }
    this.discoverers.push(discoverer);
    return discoverer;
  }

  async scan() {
    const observations = [];
    for (const discoverer of this.discoverers) {
      const found = await discoverer.scan();
      for (const peer of found || []) {
        observations.push(this.registry.observe(peer));
      }
    }
    this.registry.expire();
    return observations;
  }
}

module.exports = { PeerRegistry, AccountlessDiscovery };
