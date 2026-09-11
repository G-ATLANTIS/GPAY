'use strict';

const crypto = require('crypto');

function hash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

class ReceiptChain {
  constructor({ chainId = 'g-ether-web', maxSeenNonces = 10000 } = {}) {
    this.chainId = chainId;
    this.maxSeenNonces = maxSeenNonces;
    this.sequence = 0;
    this.headHash = null;
    this.seenNonces = new Set();
    this.nonceQueue = [];
  }

  append({ receipt, nonce }) {
    if (!receipt || typeof receipt !== 'object') throw new Error('receipt is required');
    if (!nonce || typeof nonce !== 'string') throw new Error('nonce is required');
    if (this.seenNonces.has(nonce)) {
      const err = new Error('Receipt nonce replay detected');
      err.code = 'G_RECEIPT_REPLAY';
      throw err;
    }

    const sequence = this.sequence + 1;
    const record = {
      chainId: this.chainId,
      sequence,
      nonce,
      previousHash: this.headHash,
      receiptHash: receipt.receiptHash || hash(receipt),
      recordedAt: new Date().toISOString(),
    };
    const chainHash = hash(record);

    this.sequence = sequence;
    this.headHash = chainHash;
    this.seenNonces.add(nonce);
    this.nonceQueue.push(nonce);
    if (this.nonceQueue.length > this.maxSeenNonces) {
      const expired = this.nonceQueue.shift();
      this.seenNonces.delete(expired);
    }

    return Object.freeze({ ...record, chainHash });
  }

  verifyLink({ previous, current }) {
    if (!current || current.chainId !== this.chainId) return false;
    if (!previous) return current.sequence === 1 && current.previousHash === null;
    return current.sequence === previous.sequence + 1 && current.previousHash === previous.chainHash;
  }
}

module.exports = { ReceiptChain, hash };
