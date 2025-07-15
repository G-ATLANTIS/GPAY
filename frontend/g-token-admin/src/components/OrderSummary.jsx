import React from 'react';
import MollieButton from './MollieButton';

export default function OrderSummary() {
  const order = { id: 'ORDER123', amount: '10.00' };
  return (
    <div className="p-6 border rounded shadow">
      <h2 className="text-xl mb-2">Samenvatting</h2>
      <p>Product X – €{order.amount}</p>
      <MollieButton amount={order.amount} orderId={order.id} />
    </div>
  );
}
