#!/bin/bash
set -e

echo "=== 🔁 MOLLIE ULTIMATE INTEGRATIE (MEER BETAALMETHODEN + FIXES) ==="

PROJECT_ROOT="$HOME/g-token-shopify-plugin"
BACKEND_DIR="$PROJECT_ROOT/backend"
FRONTEND_DIR="$PROJECT_ROOT/frontend/g-token-admin"
MOLLIE_KEY="${MOLLIE_API_KEY:-}"
WEBHOOK_SECRET="${MOLLIE_WEBHOOK_SECRET:-}"

cd "$BACKEND_DIR"

if [ -z "$MOLLIE_KEY" ] || [ -z "$WEBHOOK_SECRET" ]; then
  echo "ERROR: set MOLLIE_API_KEY and MOLLIE_WEBHOOK_SECRET in the environment before running this script."
  exit 1
fi

npm install @mollie/api-client fs-extra

echo "▶️ Schrijven lokale .env uit runtime environment (nooit committen)"
cat > .env << EOF
MOLLIE_API_KEY=$MOLLIE_KEY
WEBHOOK_SECRET=$WEBHOOK_SECRET
EOF

echo "▶️ Aanmaken routes/mollie.js met betaalmethoden (iDEAL, Bancontact, PayPal...)"
mkdir -p routes

cat > routes/mollie.js << 'EOF'
const express = require('express');
const fs = require('fs');
const mollieClient = require('@mollie/api-client')({ apiKey: process.env.MOLLIE_API_KEY });
const router = express.Router();

router.post('/create-payment', async (req, res) => {
  const { amount, orderId, method } = req.body;
  try {
    const payment = await mollieClient.payments.create({
      amount: { currency: 'EUR', value: amount },
      description: `Order ${orderId}`,
      redirectUrl: `http://localhost:5173/success/${orderId}`,
      webhookUrl: 'http://localhost:4000/api/mollie/webhook',
      metadata: { orderId },
      method: method || null // bv: 'ideal', 'bancontact', 'paypal'
    });
    fs.appendFileSync('logs/payments.log', `[INIT] ${orderId} ${payment.id} method=${payment.method}\n`);
    res.json({ paymentUrl: payment.getCheckoutUrl() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Payment failed' });
  }
});
EOF

echo "▶️ Aanmaken routes/webhook.js"
cat > routes/webhook.js << 'EOF'
const express = require('express');
const fs = require('fs');
const mollieClient = require('@mollie/api-client')({ apiKey: process.env.MOLLIE_API_KEY });
const router = express.Router();

router.post('/mollie/webhook', async (req, res) => {
  const id = req.body.id;
  try {
    const payment = await mollieClient.payments.get(id);
    const orderId = payment.metadata.orderId;
    fs.appendFileSync('logs/payments.log', `[WEBHOOK] ${orderId} status=${payment.status}\n`);
    res.status(200).send('OK');
  } catch (err) {
    console.error(err);
    res.status(500).send('ERROR');
  }
});
EOF

# Logging dir
mkdir -p logs

# index.js registratie
echo "▶️ Updaten backend/index.js met routes"
if ! grep -q "mollieRoutes" index.js; then
  sed -i "1i require('dotenv').config();" index.js
  sed -i "1i const mollieRoutes = require('./routes/mollie');" index.js
  sed -i "1i const webhookRoutes = require('./routes/webhook');" index.js
  sed -i "/app.use(express.json());/a app.use('/api/mollie', mollieRoutes);" index.js
  sed -i "/app.use(express.json());/a app.use('/api', webhookRoutes);" index.js
fi

# === FRONTEND UITBREIDING ===

echo "▶️ Frontend uitbreiden met meerdere betaalmethodes"

cd "$FRONTEND_DIR"
npm install axios react-select

cat > src/components/MollieButton.jsx << 'EOF'
import React, { useState } from 'react';
import axios from 'axios';

const methodOptions = [
  { label: 'iDEAL', value: 'ideal' },
  { label: 'Bancontact', value: 'bancontact' },
  { label: 'PayPal', value: 'paypal' },
  { label: 'SEPA overboeking', value: 'banktransfer' },
  { label: 'KBC', value: 'kbc' }
];

export default function MollieButton({ amount, orderId }) {
  const [method, setMethod] = useState(null);
  const [loading, setLoading] = useState(false);

  const startPayment = async () => {
    setLoading(true);
    try {
      const res = await axios.post('/api/mollie/create-payment', {
        amount,
        orderId,
        method: method?.value
      });
      window.location.href = res.data.paymentUrl;
    } catch (err) {
      alert('Betaling mislukt');
    }
    setLoading(false);
  };

  return (
    <div className="space-y-2">
      <select
        className="w-full p-2 border"
        onChange={e => setMethod({ value: e.target.value })}
      >
        <option value="">Kies betaalmethode</option>
        {methodOptions.map(opt => (
          <option key={opt.value} value={opt.value}>{opt.label}</option>
        ))}
      </select>
      <button
        onClick={startPayment}
        disabled={loading || !method}
        className="px-4 py-2 bg-green-600 text-white rounded"
      >
        {loading ? 'Verwerken...' : `Betaal €${amount}`}
      </button>
    </div>
  );
}
EOF

cat > src/pages/CheckoutPage.jsx << 'EOF'
import React from 'react';
import MollieButton from '../components/MollieButton';

export default function CheckoutPage() {
  return (
    <div className="max-w-md mx-auto mt-10">
      <h1 className="text-xl mb-4">Bestelling #ORDER456</h1>
      <MollieButton amount="15.00" orderId="ORDER456" />
    </div>
  );
}
EOF

cat > src/pages/SuccessPage.jsx << 'EOF'
import React from 'react';
import { useParams } from 'react-router-dom';

export default function SuccessPage() {
  const { orderId } = useParams();
  return (
    <div className="p-6 text-center">
      <h2 className="text-2xl font-bold">Betaling ontvangen</h2>
      <p>Order: {orderId}</p>
      <p>Bevestiging volgt via webhook.</p>
    </div>
  );
}
EOF

cat > src/App.jsx << 'EOF'
import React from 'react';
import { Routes, Route } from 'react-router-dom';
import CheckoutPage from './pages/CheckoutPage';
import SuccessPage from './pages/SuccessPage';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<CheckoutPage />} />
      <Route path="/success/:orderId" element={<SuccessPage />} />
    </Routes>
  );
}
EOF

# Router in main.jsx
if ! grep -q "BrowserRouter" src/main.jsx; then
  sed -i "1i import { BrowserRouter } from 'react-router-dom';" src/main.jsx
  sed -i "/<React.StrictMode>/a <BrowserRouter>" src/main.jsx
  sed -i "/<\/React.StrictMode>/i </BrowserRouter>" src/main.jsx
fi

echo ""
echo "✅ MOLLIE ULTIMATE INTEGRATIE VOLTOOID"
echo "- Back-end gebruikt alleen runtime environment secrets + webhook logging"
echo "- Front-end ondersteunt meerdere betaalmethoden"
echo "- Start backend met: cd $BACKEND_DIR && node index.js"
echo "- Start frontend met: cd $FRONTEND_DIR && npm run dev"
echo "- Surf naar: http://localhost:5173/ en test met ORDER456"
