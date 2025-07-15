exports.logStatus = (req, res) => {
  res.sendFile('payments.log', { root: './logs' });
};
