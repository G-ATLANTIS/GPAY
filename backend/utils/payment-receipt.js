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
  settlementEventId = null,
  settlementMode = null,
  settlementExecutionStatus = null,
  settlementContractAddress = null,
  settlementChainId = null,
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
    settlementEventId,
    settlementMode,
    settlementExecutionStatus,
    settlementContractAddress,
    settlementChainId,
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
