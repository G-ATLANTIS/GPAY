import React, { useState } from 'react';
import axios from 'axios';

export default function PulsePayButton() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const createPayment = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post('/api/pulsepay/create-payment', {
        amount: 1000,
        currency: 'EUR',
        userId: 'user123',
      });
      if (response.data.paymentUrl) {
        window.location.href = response.data.paymentUrl;
      } else {
        setError('Geen betalings-URL ontvangen.');
      }
    } catch (err) {
      setError('Kan betaling niet aanmaken.');
    }
    setLoading(false);
  };

  return (
    <div>
      <button
        onClick={createPayment}
        disabled={loading}
        className="px-4 py-2 bg-blue-600 text-white rounded"
      >
        {loading ? 'Verwerken...' : 'Betaal met PulsePay'}
      </button>
      {error && <p className="text-red-600 mt-2">{error}</p>}
    </div>
  );
}
