require('dotenv').config();

const express = require('express');
const openBankingRoutes = require('./routes/openbanking');

const app = express();
const PORT = Number(process.env.PORT || 4000);

const openBankingJson = express.json({
  limit: '64kb',
  verify: (req, res, buffer) => {
    req.rawBody = Buffer.from(buffer);
  }
});

app.use('/api/open-banking', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  next();
}, openBankingJson, openBankingRoutes, (req, res) => {
  res.status(404).json({
    error: 'Unknown G-Bank route.',
    verified_value_flow: false
  });
});

app.get('/', (req, res) => {
  res.type('text/plain').send('G-Bank readiness server');
});

const server = app.listen(PORT, '127.0.0.1', () => {
  console.log(`G-Bank readiness server listening on 127.0.0.1:${PORT}`);
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 3000).unref();
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
