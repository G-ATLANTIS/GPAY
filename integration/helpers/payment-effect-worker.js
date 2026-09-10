const { Pool } = require('pg');
const { PostgresPaymentEffectLedger } = require('../../backend/utils/payment-effect-ledger');

async function main() {
  const [operation, provider, paymentId, effectType, payloadJson = '{}'] = process.argv.slice(2);
  const connectionString = process.env.GPAY_POSTGRES_URL;
  if (!connectionString) throw new Error('GPAY_POSTGRES_URL is required');

  const pool = new Pool({ connectionString, max: 2 });
  const ledger = new PostgresPaymentEffectLedger(pool);
  try {
    await ledger.ensureReady();
    const payload = JSON.parse(payloadJson);
    let result;
    if (operation === 'prepare') result = await ledger.prepare(provider, paymentId, effectType, payload);
    else if (operation === 'complete') result = await ledger.complete(provider, paymentId, effectType, payload);
    else if (operation === 'get') result = await ledger.get(provider, paymentId, effectType);
    else throw new Error(`Unsupported operation: ${operation}`);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  process.stderr.write(`${JSON.stringify({ message: err.message, code: err.code || null })}\n`);
  process.exitCode = 1;
});
