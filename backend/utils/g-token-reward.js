module.exports = function rewardTokens(amountEUR, userId) {
  const reward = parseFloat(amountEUR) * 10;
  console.log(`[G‑TOKEN] ${reward} tokens toegekend aan ${userId}`);
  return reward;
};
