const nodemailer = require('nodemailer');

function requireMailConfig() {
  if (!process.env.EMAIL_FROM || !process.env.EMAIL_PASS) {
    const err = new Error('EMAIL_FROM and EMAIL_PASS are required for mail delivery');
    err.code = 'MAIL_CONFIG_ERROR';
    throw err;
  }
}

module.exports = function sendConfirmation(email, invoicePath) {
  requireMailConfig();
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_FROM,
      pass: process.env.EMAIL_PASS,
    },
  });

  return transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: email,
    subject: 'Bevestiging betaling',
    text: 'Dank voor je betaling!',
    attachments: [{ filename: 'factuur.pdf', path: invoicePath }],
  });
};
