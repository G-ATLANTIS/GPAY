const { canonicalReceiptPayload } = require('./payment-receipt');
const crypto = require('crypto');

function verifyReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object' || typeof receipt.receiptHash !== 'string') {
    return false;
  }

  const payload = canonicalReceiptPayload(receipt);
  const actual = crypto.createHash('sha256').update(payload).digest('hex');

  try {
    return crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(receipt.receiptHash, 'hex'));
  } catch {
    return false;
  }
}

module.exports = { verifyReceipt };
