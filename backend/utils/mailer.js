const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_FROM,
    pass: process.env.EMAIL_PASS,
  },
});
module.exports = function sendConfirmation(email, invoicePath) {
  return transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: email,
    subject: 'Bevestiging betaling',
    text: 'Dank voor je betaling!',
    attachments: [{ filename: 'factuur.pdf', path: invoicePath }],
  });
};
