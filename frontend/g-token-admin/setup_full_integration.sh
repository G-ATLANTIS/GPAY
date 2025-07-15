#!/bin/bash
set -e

echo "=== COMPLETE SETUP FRONTEND + BACKEND INTEGRATIE ==="

# Paden
PROJECT_ROOT="$HOME/g-token-shopify-plugin"
FRONTEND_DIR="$PROJECT_ROOT/frontend/g-token-admin"
BACKEND_DIR="$PROJECT_ROOT/backend"

# --- FRONTEND ---

echo "Stap 1: Frontend TailwindCSS + walletconnect setup"

cd "$FRONTEND_DIR"

# TailwindCSS installatie
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p

# tailwind.config.js overschrijven
cat > tailwind.config.js << EOF
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: { extend: {} },
  plugins: [],
}
EOF

# index.css aanmaken / overschrijven
cat > src/index.css << EOF
@tailwind base;
@tailwind components;
@tailwind utilities;
EOF

# index.css importeren in main.jsx
if ! grep -q "import './index.css'" src/main.jsx; then
  sed -i "1i import './index.css';" src/main.jsx
fi

# Installeren walletconnect en ethers dependencies
npm install @web3-react/core @web3-react/injected-connector ethers

# Maak WalletConnect component aan
mkdir -p src/components
cat > src/components/WalletConnect.jsx << 'EOF'
import React, { useEffect, useState } from 'react';
import { ethers } from 'ethers';
import { InjectedConnector } from '@web3-react/injected-connector';
import { useWeb3React } from '@web3-react/core';

const injected = new InjectedConnector({ supportedChainIds: [1, 5, 137] });

export default function WalletConnect() {
  const { active, account, activate, deactivate, library } = useWeb3React();
  const [balance, setBalance] = useState(null);

  useEffect(() => {
    if (active && library && account) {
      library.getBalance(account).then((balance) => {
        setBalance(ethers.utils.formatEther(balance));
      });
    }
  }, [active, library, account]);

  return (
    <div className="p-4 border rounded shadow-md max-w-sm mx-auto">
      {active ? (
        <>
          <p>Connected account: {account}</p>
          <p>Balance: {balance} ETH</p>
          <button
            onClick={() => deactivate()}
            className="mt-2 px-4 py-2 bg-red-600 text-white rounded"
          >
            Disconnect
          </button>
        </>
      ) : (
        <button
          onClick={() => activate(injected)}
          className="px-4 py-2 bg-green-600 text-white rounded"
        >
          Connect Metamask
        </button>
      )}
    </div>
  );
}
EOF

# Voeg WalletConnect toe aan App.jsx als dat nog niet gedaan is
if ! grep -q "WalletConnect" src/App.jsx; then
  sed -i "1i import WalletConnect from './components/WalletConnect.jsx';" src/App.jsx
  sed -i "/function App()/a\\
  return (\\
    <div className=\"App\">\\
      <WalletConnect />\\
    </div>\\
  );" src/App.jsx
fi

# Wrap met Web3ReactProvider in main.jsx als nog niet gedaan
if ! grep -q "Web3ReactProvider" src/main.jsx; then
  sed -i "1i import { Web3ReactProvider } from '@web3-react/core';\nimport { ethers } from 'ethers';" src/main.jsx
  sed -i "/ReactDOM.createRoot(/a\\
function getLibrary(provider) { return new ethers.providers.Web3Provider(provider); }\\
" src/main.jsx
  sed -i "s|<React.StrictMode>|<React.StrictMode>\\
    <Web3ReactProvider getLibrary={getLibrary}>|" src/main.jsx
  sed -i "s|</React.StrictMode>|</Web3ReactProvider>\\
  </React.StrictMode>|" src/main.jsx
fi

# --- BACKEND ---

echo "Stap 2: Backend Shopify webhook route aanmaken"

mkdir -p "$BACKEND_DIR/routes"

cat > "$BACKEND_DIR/routes/shopify.js" << 'EOF'
const express = require('express');
const router = express.Router();

// Shopify webhook endpoint
router.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const payload = req.body;
  console.log('Shopify webhook ontvangen:', payload);
  // TODO: HMAC validatie en payload verwerking
  res.status(200).send('Webhook ontvangen');
});

module.exports = router;
EOF

# Voeg route toe aan backend/index.js als niet al gedaan
if ! grep -q "shopifyRoutes" "$BACKEND_DIR/index.js"; then
  sed -i "1i const shopifyRoutes = require('./routes/shopify');" "$BACKEND_DIR/index.js"
  sed -i "/app.use(express.json());/a app.use('/api/shopify', shopifyRoutes);" "$BACKEND_DIR/index.js"
fi

echo "Setup voltooid! Je kunt nu frontend starten met 'npm run dev' in $FRONTEND_DIR"
echo "Start backend met 'node index.js' in $BACKEND_DIR"
