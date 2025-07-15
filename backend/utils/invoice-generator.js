const PDFDocument = require('pdfkit');
const fs = require('fs');
module.exports = function generateInvoice(orderId, amount, email) {
  const doc = new PDFDocument();
  const filename = `invoices/${orderId}.pdf`;
  doc.pipe(fs.createWriteStream(filename));
  doc.fontSize(20).text('Factuur – G‑PAY™', { align: 'center' });
  doc.moveDown().fontSize(14).text(`Order: ${orderId}\nBedrag: €${amount}\nKlant: ${email}`);
  doc.end();
  return filename;
};
