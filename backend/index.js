const mollieRoutes = require('./routes/mollie');
const pulsepayRoutes = require('./routes/pulsepay');
const webhookRoutes = require('./routes/webhook');
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());
app.use('/api/mollie', mollieRoutes);
app.use('/api/pulsepay', pulsepayRoutes);
app.use('/api', webhookRoutes);

app.get('/', (req, res) => {
  res.send('G-Token Shopify Plugin Backend is running');
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;
