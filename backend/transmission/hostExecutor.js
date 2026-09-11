'use strict';

class HostMediatedExecutor {
  constructor({ enumerateDevices, probeDevice, transmitDevice } = {}) {
    if (typeof enumerateDevices !== 'function') throw new Error('enumerateDevices function is required');
    if (typeof probeDevice !== 'function') throw new Error('probeDevice function is required');
    if (typeof transmitDevice !== 'function') throw new Error('transmitDevice function is required');
    this.enumerateDevices = enumerateDevices;
    this.probeDevice = probeDevice;
    this.transmitDevice = transmitDevice;
  }

  async enumerate() {
    const devices = await this.enumerateDevices();
    if (!Array.isArray(devices)) throw new Error('enumerateDevices must return an array');
    return devices;
  }

  async execute(request = {}) {
    const { action, devicePath, authorizationEvidence, executionIntent = false } = request;
    if (!action) throw new Error('action is required');

    if (action === 'verify') {
      if (!devicePath) {
        const error = new Error('devicePath is required for verify');
        error.code = 'G_HOST_DEVICE_PATH_REQUIRED';
        throw error;
      }
      if (!authorizationEvidence) {
        const error = new Error('authorization evidence is required for verify');
        error.code = 'G_HOST_AUTH_REQUIRED';
        throw error;
      }
      const result = await this.probeDevice({ ...request, action: 'verify' });
      return {
        ...result,
        action: 'verify',
        devicePath,
        transmitted: false,
      };
    }

    if (action === 'transmit') {
      if (!devicePath) {
        const error = new Error('devicePath is required for transmit');
        error.code = 'G_HOST_DEVICE_PATH_REQUIRED';
        throw error;
      }
      if (!authorizationEvidence) {
        const error = new Error('authorization evidence is required for transmit');
        error.code = 'G_HOST_AUTH_REQUIRED';
        throw error;
      }
      if (executionIntent !== true) {
        const error = new Error('explicit execution intent is required for transmit');
        error.code = 'G_HOST_EXECUTION_INTENT_REQUIRED';
        throw error;
      }
      const result = await this.transmitDevice({ ...request, action: 'transmit' });
      return {
        ...result,
        action: 'transmit',
        devicePath,
        transmitted: true,
      };
    }

    const error = new Error(`unsupported host executor action: ${action}`);
    error.code = 'G_HOST_ACTION_UNSUPPORTED';
    throw error;
  }
}

function bindHostExecutor(hostExecutor, { authorizationEvidence, executionIntent = false } = {}) {
  if (!hostExecutor || typeof hostExecutor.execute !== 'function') {
    throw new Error('hostExecutor with execute() is required');
  }
  return async (request = {}) => hostExecutor.execute({
    ...request,
    authorizationEvidence,
    executionIntent: request.action === 'transmit' ? executionIntent : false,
  });
}

module.exports = { HostMediatedExecutor, bindHostExecutor };
