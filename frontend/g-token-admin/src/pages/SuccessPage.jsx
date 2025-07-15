import React from 'react';
import { useParams } from 'react-router-dom';
export default function SuccessPage() {
  const { orderId } = useParams();
  return <div className="p-6">✅ Betaling ontvangen: {orderId}</div>;
}
