import React from 'react';
import axios from 'axios';
export default function CheckoutPage() {
  const start = async () => {
    const res = await axios.post('/api/mollie/create-payment', {
      amount: '10.00',
      orderId: 'ORDER999',
      email: 'klant@example.com'
    });
    window.location.href = res.data.paymentUrl;
  };
  return <button onClick={start} className="p-4 bg-blue-600 text-white rounded">Betaal €10</button>;
}
