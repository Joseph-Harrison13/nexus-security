const nodemailer = require('nodemailer');

let _transporter = null;

function getTransporter() {
  if (_transporter) return _transporter;
  const { EMAIL_USER, EMAIL_PASS, EMAIL_HOST, EMAIL_PORT } = process.env;
  if (!EMAIL_USER || !EMAIL_PASS || EMAIL_USER === 'your@email.com') return null;
  _transporter = nodemailer.createTransport({
    host:   EMAIL_HOST  || 'smtp.gmail.com',
    port:   parseInt(EMAIL_PORT || '587', 10),
    secure: false,
    auth: { user: EMAIL_USER, pass: EMAIL_PASS },
  });
  return _transporter;
}

async function sendMail({ to, subject, text, html }) {
  const transporter = getTransporter();
  const dest = to || process.env.EMAIL_TO || process.env.EMAIL_USER;
  if (!transporter || !dest) {
    console.log(`[mailer] Not configured — would have sent "${subject}" to ${dest}`);
    return false;
  }
  try {
    await transporter.sendMail({
      from:    process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to:      dest,
      subject, text, html,
    });
    return true;
  } catch (err) {
    console.error('[mailer] Send failed:', err.message);
    return false;
  }
}

module.exports = { sendMail };
