const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const args = process.argv.slice(2);
const force = args.includes('--force');
const outArgIndex = args.indexOf('--out-dir');
const outDir = path.resolve(
  outArgIndex >= 0 && args[outArgIndex + 1]
    ? args[outArgIndex + 1]
    : path.join(process.cwd(), '.secrets', 'truelayer')
);

const privatePath = path.join(outDir, 'ec512-private-key.pem');
const publicPath = path.join(outDir, 'ec512-public-key.pem');

if (!force && (fs.existsSync(privatePath) || fs.existsSync(publicPath))) {
  console.error('Refusing to overwrite an existing TrueLayer keypair. Use --force only when intentional.');
  process.exit(2);
}

fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });

const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'secp521r1'
});

const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

fs.writeFileSync(privatePath, privatePem, { mode: 0o600 });
fs.writeFileSync(publicPath, publicPem, { mode: 0o644 });

console.log('TrueLayer P-521 signing keypair generated.');
console.log('Private key:', privatePath);
console.log('Public key :', publicPath);
console.log('Upload ONLY the public key to TrueLayer Console.');
console.log('Do not commit or share the private key.');
