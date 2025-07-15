module.exports = function checkFraud(ip, amount, ua) {
  if (parseFloat(amount) > 999 || ua.includes('bot')) {
    console.warn(`[FRAUDE] Mogelijk verdacht: ${ip} ${amount}`);
    return true;
  }
  return false;
};
