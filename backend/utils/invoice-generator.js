const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

module.exports = function generateInvoice(orderId, amount, email) {
  return new Promise((resolve, reject) => {
    const invoiceDir = path.join(process.cwd(), 'invoices');
    fs.mkdirSync(invoiceDir, { recursive: true });
    const filename = path.join(invoiceDir, `${String(orderId).replace(/[^a-zA-Z0-9._-]/g, '_')}.pdf`);

    const doc = new PDFDocument();
    const stream = fs.createWriteStream(filename, { flags: 'w', mode: 0o600 });
    stream.on('finish', () => resolve(filename));
    stream.on('error', reject);
    doc.on('error', reject);

    doc.pipe(stream);
    doc.fontSize(20).text('Factuur – G‑PAY™', { align: 'center' });
    doc.moveDown().fontSize(14).text(`Order: ${orderId}\nBedrag: €${amount}\nKlant: ${email}`);
    doc.end();
  });
};
