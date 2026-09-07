require('dotenv').config();

const mollieRoutes = require('./routes/mollie');
const pulsepayRoutes = require('./routes/pulsepay');
const openBankingRoutes = require('./routes/openbanking');
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json({
  verify: (req, res, buffer) => {
    if (req.originalUrl && req.originalUrl.startsWith('/api/open-banking/webhook')) {
      req.rawBody = Buffer.from(buffer);
    }
  }
}));
app.use('/api/mollie', mollieRoutes);
app.use('/api/pulsepay', pulsepayRoutes);
app.use('/api/open-banking', openBankingRoutes);

app.get('/', (req, res) => {
  res.send('G-Token Shopify Plugin Backend is running');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
