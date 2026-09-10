const crypto = require('crypto');

function canonicalReceiptPayload({
  provider,
  providerPaymentId,
  orderId,
  amount,
  currency,
  status,
  processedAt,
  rewardEventId = null,
}) {
  return JSON.stringify({
    provider,
    providerPaymentId,
    orderId,
    amount,
    currency,
    status,
    processedAt,
    rewardEventId,
  });
}

function createReceipt(input) {
  const payload = canonicalReceiptPayload(input);
  return {
    ...input,
    receiptHash: crypto.createHash('sha256').update(payload).digest('hex'),
  };
}

module.exports = { canonicalReceiptPayload, createReceipt };
