import React from 'react';
import QRCode from 'qrcode.react';
export default function KioskQRCode({ url }) {
  return (
    <div className="p-6 text-center">
      <h2>Scan & Betaal</h2>
      <QRCode value={url} size={256} />
    </div>
  );
}
