require('dotenv').config();
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

// Basic route
app.get('/', (req, res) => {
  res.send('G-Token Shopify Plugin Backend is running');
});

// TODO: Add routes for Shopify webhook, token transactions, admin auth

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
