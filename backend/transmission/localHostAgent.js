'use strict';

const path = require('path');

const ALLOWED_COMMANDS = new Set(['rnstatus', 'rnprobe']);

class LocalHostAgent {
  constructor({ hostId, listDevicePaths, commandExecutor } = {}) {
    if (!hostId) throw new Error('hostId is required');
    if (typeof listDevicePaths !== 'function') throw new Error('listDevicePaths function is required');
    if (typeof commandExecutor !== 'function') throw new Error('commandExecutor function is required');
    this.hostId = hostId;
    this.listDevicePaths = listDevicePaths;
    this.commandExecutor = commandExecutor;
  }

  async enumerate() {
    const paths = await this.listDevicePaths();
    if (!Array.isArray(paths)) throw new Error('listDevicePaths must return an array');
    return paths.map((devicePath) => ({
      hostId: this.hostId,
      path: devicePath,
      basename: path.basename(devicePath),
      observed: true,
      authorized: false,
      transmitted: false,
    }));
  }

  async runAllowed(command, args = []) {
    if (!ALLOWED_COMMANDS.has(command)) {
      const error = new Error('Command is not allowed by local host agent');
      error.code = 'G_HOST_COMMAND_DENIED';
      throw error;
    }
    return this.commandExecutor({ command, args: [...args] });
  }

  async probeReticulum() {
    const result = await this.runAllowed('rnstatus', []);
    if (!result || result.ok !== true) {
      const error = new Error('Reticulum status probe failed');
      error.code = 'G_RETICULUM_PROBE_FAILED';
      throw error;
    }
    return Object.freeze({
      hostId: this.hostId,
      status: 'READY_NO_SEND',
      bearer: 'RETICULUM',
      transmitted: false,
      authorizationGranted: false,
      result,
      observedAt: new Date().toISOString(),
    });
  }

  async transmitReticulum({ destination, payload, authorizationEvidence, executionIntent = false } = {}) {
    if (!destination || payload === undefined || payload === null) throw new Error('destination and payload are required');
    if (!authorizationEvidence) {
      const error = new Error('authorization evidence is required');
      error.code = 'G_HOST_AUTH_REQUIRED';
      throw error;
    }
    if (executionIntent !== true) {
      const error = new Error('explicit execution intent is required');
      error.code = 'G_HOST_EXECUTION_INTENT_REQUIRED';
      throw error;
    }
    return this.runAllowed('rnprobe', [String(destination), String(payload)]);
  }
}

module.exports = { LocalHostAgent, ALLOWED_COMMANDS };
