#!/bin/bash
set -e

echo "=== Minimalistische TailwindCSS + WalletConnect Installatie ==="

FRONTEND_DIR="$HOME/g-token-shopify-plugin/frontend/g-token-admin"

cd "$FRONTEND_DIR"

# Check of package.json bestaat
if [ ! -f "package.json" ]; then
  echo "Fout: package.json niet gevonden in $FRONTEND_DIR"
  echo "Voer eerst 'npm init -y' en 'npm install' handmatig uit."
  exit 1
fi

# Verwijder oude node_modules en lock file
echo "Verwijder oude node_modules en package-lock.json (indien aanwezig)..."
rm -rf node_modules package-lock.json

# Nieuwe install
echo "Voer npm install uit..."
npm install

# Installeer TailwindCSS + peer dependencies
echo "Installeer TailwindCSS en dependencies..."
npm install -D tailwindcss postcss autoprefixer

# Initialiseer Tailwind config en postcss config
npx tailwindcss init -p

# Installeer walletconnect en ethers
echo "Installeer walletconnect en ethers..."
npm install @web3-react/core @web3-react/injected-connector ethers

echo "Installatie voltooid. Pas nu tailwind.config.js en css bestanden aan zoals nodig."
