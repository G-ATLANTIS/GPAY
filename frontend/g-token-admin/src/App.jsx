import React from 'react';
import { Routes, Route } from 'react-router-dom';
import CheckoutPage from './pages/CheckoutPage';
import SuccessPage from './pages/SuccessPage';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<CheckoutPage />} />
      <Route path="/success/:orderId" element={<SuccessPage />} />
    </Routes>
  );
}
