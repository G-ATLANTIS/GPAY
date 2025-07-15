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
