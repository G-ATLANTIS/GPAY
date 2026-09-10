const crypto = require('crypto');

const GCOIN = Object.freeze({
  name: 'G Coin',
  symbol: 'GCOIN',
  network: 'ethereum-mainnet',
  chainId: 1,
  contractAddress: '0xF2923D79903Aa13a62d408b4fabF748dB87B8c30',
  decimals: 18,
});

function requireText(value, name) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new TypeError(`${name} is required`);
  }
  return value.trim();
}

function createGcoinSettlementIntent({
  provider,
  providerPaymentId,
  orderId,
  amount,
  currency,
  rewardEventId,
  gcoinAmount,
  broadcast = false,
}) {
  if (broadcast !== false) {
    const err = new Error('GCOIN broadcast is disabled: settlement intent is verification-only');
    err.code = 'GCOIN_BROADCAST_DENIED';
    throw err;
  }

  const canonical = {
    provider: requireText(provider, 'provider'),
    providerPaymentId: requireText(providerPaymentId, 'providerPaymentId'),
    orderId: requireText(orderId, 'orderId'),
    amount: requireText(String(amount), 'amount'),
    currency: requireText(currency, 'currency').toUpperCase(),
    rewardEventId: requireText(rewardEventId, 'rewardEventId'),
    gcoinAmount: requireText(String(gcoinAmount), 'gcoinAmount'),
    asset: GCOIN.symbol,
    network: GCOIN.network,
    chainId: GCOIN.chainId,
    contractAddress: GCOIN.contractAddress,
  };

  const settlementEventId = crypto
    .createHash('sha256')
    .update(JSON.stringify(canonical))
    .digest('hex');

  return Object.freeze({
    ...canonical,
    settlementEventId,
    mode: 'intent_only',
    executionStatus: 'not_attempted',
    broadcast: false,
    signerUsed: false,
    transactionHash: null,
  });
}

module.exports = { GCOIN, createGcoinSettlementIntent };
