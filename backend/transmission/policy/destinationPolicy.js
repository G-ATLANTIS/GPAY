'use strict';

const crypto = require('crypto');

function stableHash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

class DestinationPolicyRegistry {
  constructor() {
    this.destinations = new Map();
    this.routes = new Map();
  }

  allowDestination({ destinationId, address, transportKinds = [] }) {
    if (!destinationId || !address) throw new Error('destinationId and address are required');
    const record = Object.freeze({
      destinationId,
      address,
      transportKinds: [...transportKinds].sort(),
      policyHash: stableHash({ destinationId, address, transportKinds: [...transportKinds].sort() }),
    });
    this.destinations.set(destinationId, record);
    return record;
  }

  revokeDestination(destinationId) {
    this.destinations.delete(destinationId);
    for (const [routeId, route] of this.routes.entries()) {
      if (route.destinationId === destinationId) this.routes.delete(routeId);
    }
  }

  bindRoute({ routeId, destinationId, backendKind }) {
    const destination = this.destinations.get(destinationId);
    if (!destination) {
      const err = new Error('Destination is not allowlisted');
      err.code = 'G_DESTINATION_NOT_ALLOWED';
      throw err;
    }
    if (destination.transportKinds.length && !destination.transportKinds.includes(backendKind)) {
      const err = new Error('Backend kind is not permitted for destination');
      err.code = 'G_DESTINATION_TRANSPORT_DENIED';
      throw err;
    }
    const route = Object.freeze({
      routeId,
      destinationId,
      backendKind,
      routePolicyHash: stableHash({ routeId, destinationId, backendKind, destinationPolicyHash: destination.policyHash }),
    });
    this.routes.set(routeId, route);
    return route;
  }

  authorize({ routeId, destinationId, address, backendKind }) {
    const destination = this.destinations.get(destinationId);
    if (!destination) {
      const err = new Error('Destination is not allowlisted');
      err.code = 'G_DESTINATION_NOT_ALLOWED';
      throw err;
    }
    if (destination.address !== address) {
      const err = new Error('Destination address mismatch');
      err.code = 'G_DESTINATION_ADDRESS_MISMATCH';
      throw err;
    }
    const route = this.routes.get(routeId);
    if (!route || route.destinationId !== destinationId || route.backendKind !== backendKind) {
      const err = new Error('Route policy mismatch');
      err.code = 'G_ROUTE_POLICY_MISMATCH';
      throw err;
    }
    return Object.freeze({
      routeId,
      destinationId,
      address,
      backendKind,
      destinationPolicyHash: destination.policyHash,
      routePolicyHash: route.routePolicyHash,
      authorizedAt: new Date().toISOString(),
    });
  }
}

module.exports = { DestinationPolicyRegistry, stableHash };
