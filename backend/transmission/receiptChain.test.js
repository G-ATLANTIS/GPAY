'use strict';

const assert = require('assert');
const { ReceiptChain } = require('./receiptChain');

(function run() {
  const chain = new ReceiptChain({ chainId: 'test-chain' });
  const first = chain.append({ receipt: { receiptHash: 'r1' }, nonce: 'n1' });
  const second = chain.append({ receipt: { receiptHash: 'r2' }, nonce: 'n2' });

  assert.equal(first.sequence, 1);
  assert.equal(first.previousHash, null);
  assert.equal(second.sequence, 2);
  assert.equal(second.previousHash, first.chainHash);
  assert.equal(chain.verifyLink({ previous: null, current: first }), true);
  assert.equal(chain.verifyLink({ previous: first, current: second }), true);

  let replay = false;
  try {
    chain.append({ receipt: { receiptHash: 'r3' }, nonce: 'n2' });
  } catch (err) {
    replay = err.code === 'G_RECEIPT_REPLAY';
  }
  assert.equal(replay, true);

  const tampered = { ...second, previousHash: 'bad' };
  assert.equal(chain.verifyLink({ previous: first, current: tampered }), false);

  console.log('receiptChain.test.js: PASS');
})();
