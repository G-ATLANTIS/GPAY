require('dotenv').config();

const mollieRoutes = require('./routes/mollie');
const pulsepayRoutes = require('./routes/pulsepay');
const openBankingRoutes = require('./routes/openbanking');
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 4000;

const openBankingJson = express.json({
  limit: '64kb',
  verify: (req, res, buffer) => {
    // Preserve exact bytes for TrueLayer webhook signature verification.
    req.rawBody = Buffer.from(buffer);
  }
});

app.use('/api/open-banking', (req, res, next) => {
  // G-Bank is server-to-server/operator-facing. Do not expose it through the
  // application's general browser CORS policy.
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

app.use(cors());
app.use(express.json());
app.use('/api/mollie', mollieRoutes);
app.use('/api/pulsepay', pulsepayRoutes);

app.get('/', (req, res) => {
  res.send('G-Token Shopify Plugin Backend is running');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
