'use strict';

class AuthorizedSerialRadioBackend {
  constructor({ id, kind, devicePath, authorizationEvidence = null, executor = null }) {
    if (!id || !kind || !devicePath) throw new Error('id, kind, and devicePath are required');
    this.id = id;
    this.kind = kind;
    this.devicePath = devicePath;
    this.authorizationEvidence = authorizationEvidence;
    this.executor = executor;
    this.verified = false;
  }

  assertAuthorized() {
    if (!this.authorizationEvidence) {
      const error = new Error(`radio ${this.id} lacks authorization evidence`);
      error.code = 'G_RADIO_AUTH_REQUIRED';
      throw error;
    }
    if (!this.executor) {
      const error = new Error(`radio ${this.id} has no local executor`);
      error.code = 'G_RADIO_EXECUTOR_REQUIRED';
      throw error;
    }
  }

  async verify() {
    this.assertAuthorized();
    const result = await this.executor({
      action: 'verify',
      kind: this.kind,
      devicePath: this.devicePath,
    });
    if (!result || result.ok !== true) {
      const error = new Error(`radio ${this.id} verification failed`);
      error.code = 'G_RADIO_VERIFY_FAILED';
      throw error;
    }
    this.verified = true;
    return result;
  }

  async transmit({ payload, destination = null, parameters = {} }) {
    this.assertAuthorized();
    if (!this.verified) {
      const error = new Error(`radio ${this.id} has not passed verification`);
      error.code = 'G_RADIO_NOT_VERIFIED';
      throw error;
    }
    return this.executor({
      action: 'transmit',
      kind: this.kind,
      devicePath: this.devicePath,
      payload,
      destination,
      parameters,
    });
  }
}

class RNodeBackend extends AuthorizedSerialRadioBackend {
  constructor(options) {
    super({ ...options, kind: 'RNODE' });
  }
}

class KissTncBackend extends AuthorizedSerialRadioBackend {
  constructor(options) {
    super({ ...options, kind: 'KISS_TNC' });
  }
}

class GenericSerialBackend extends AuthorizedSerialRadioBackend {
  constructor(options) {
    super({ ...options, kind: 'GENERIC_SERIAL_RADIO' });
  }
}

module.exports = {
  AuthorizedSerialRadioBackend,
  RNodeBackend,
  KissTncBackend,
  GenericSerialBackend,
};
