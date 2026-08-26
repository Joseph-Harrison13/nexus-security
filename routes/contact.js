const express    = require('express');
const db         = require('../db/database');
const validate   = require('../middleware/validate');
const { schemas } = require('../lib/schemas');
const { sendMail } = require('../lib/mailer');
const { csvRow } = require('../lib/csv');
// Marketing/contact leads belong to the platform, not any client org, so only
// the platform owner (SuperAdmin) may read them.
const { requireSuperAdmin: requireAdmin } = require('../middleware/auth');

const router = express.Router();

// Escape user-supplied values before embedding them in the notification email's
// HTML body. Email clients block scripts, so this isn't about code execution —
// it stops a stranger injecting markup/links to spoof the email's content.
function escHtml(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// POST /api/contact
router.post('/', validate(schemas.contact), async (req, res) => {
  const { firstName, lastName, email, businessName, interestedIn, message } = req.body;

  db.prepare(`
    INSERT INTO contact_submissions (first_name, last_name, email, business_name, interested_in, message)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(firstName, lastName, email, businessName, interestedIn, message);

  await sendMail({
    to:      process.env.EMAIL_TO || process.env.EMAIL_USER,
    subject: `New Contact Form Submission — ${businessName || email}`,
    text: [`From: ${firstName || ''} ${lastName || ''} <${email}>`, `Business: ${businessName || 'N/A'}`, `Interested in: ${interestedIn || 'N/A'}`, '', message].join('\n'),
    html: `<h2>New Contact Form Submission</h2><p><strong>Name:</strong> ${escHtml(firstName)} ${escHtml(lastName)}</p><p><strong>Email:</strong> ${escHtml(email)}</p><p><strong>Business:</strong> ${escHtml(businessName) || 'N/A'}</p><p><strong>Interested in:</strong> ${escHtml(interestedIn) || 'N/A'}</p><hr/><p>${escHtml(message).replace(/\n/g, '<br>')}</p>`,
  });

  res.json({ message: 'Message received — we will be in touch within 2 business hours.' });
});

// GET /api/contact  — admin only
router.get('/', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM contact_submissions ORDER BY submitted_at DESC').all());
});

// GET /api/contact/export/csv — admin only
router.get('/export/csv', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM contact_submissions ORDER BY submitted_at DESC').all();
  const header = 'id,first_name,last_name,email,business_name,interested_in,message,submitted_at\n';
  const csv = rows.map(r =>
    csvRow([r.id, r.first_name || '', r.last_name || '', r.email,
            r.business_name || '', r.interested_in || '', r.message || '', r.submitted_at])
  ).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="leads.csv"');
  res.send(header + csv);
});

module.exports = router;
