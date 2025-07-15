const mollieRoutes = require('./routes/mollie');
const pulsepayRoutes = require('./routes/pulsepay');
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 4000;

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
