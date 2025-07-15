import React from 'react';
import { useParams } from 'react-router-dom';

export default function PaymentStatus() {
  const { orderId } = useParams();
  return (
    <div className="p-6 text-center">
      <h2 className="text-2xl font-bold">Bedankt voor je betaling!</h2>
      <p>Order-ID: {orderId}</p>
      <p>Status wordt verwerkt via webhook.</p>
    </div>
  );
}
