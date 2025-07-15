#!/usr/bin/env node
const fs = require('fs');
const crypto = require('crypto');

const LICENSE_PATH = process.env.HOME + '/.gpay-license';
const args = process.argv.slice(2);

function generateKey(user) {
  return crypto.createHash('sha256').update(user + Date.now()).digest('hex').slice(0, 32);
}

if (args[0] === 'activate') {
  const key = args[1];
  fs.writeFileSync(LICENSE_PATH, key);
  console.log('🔓 G‑PAY™ geactiveerd met sleutel:', key);
} else if (args[0] === 'status') {
  if (fs.existsSync(LICENSE_PATH)) {
    console.log('✅ Licentie actief:', fs.readFileSync(LICENSE_PATH, 'utf8'));
  } else {
    console.log('❌ Geen actieve licentie gevonden.');
  }
} else {
  console.log('Gebruik: gpay-license activate <key> | status');
}
