import { useEffect, useState } from 'react';
import axios from 'axios';
export default function usePaymentStatus(orderId) {
  const [status, setStatus] = useState('pending');
  useEffect(() => {
    const intv = setInterval(() => {
      axios.get('/api/status/' + orderId).then(res => setStatus(res.data.status));
    }, 3000);
    return () => clearInterval(intv);
  }, [orderId]);
  return status;
}
