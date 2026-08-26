const express  = require('express');
const crypto   = require('crypto');
const db       = require('../db/database');
const { sendMail } = require('../lib/mailer');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

function hashToken(t) { return crypto.createHash('sha256').update(t).digest('hex'); }

// Issue a fresh verification token and email it. Reused by registration and the
// authenticated "resend" route. Returns the sendMail result.
async function sendVerificationEmail(user) {
  const token     = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  db.prepare('DELETE FROM email_verifications WHERE user_id = ?').run(user.id);
  db.prepare('INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES (?, ?, ?)').run(user.id, tokenHash, expiresAt);

  const verifyUrl = `${process.env.SITE_URL || 'https://localhost:3443'}/pages/verify-email.html?token=${token}`;
  return sendMail({
    to:      user.email,
    subject: 'Verify your Nexus Security email address',
    text:    `Hi ${user.name},\n\nClick this link to verify your email:\n${verifyUrl}\n\nThis link expires in 24 hours.\n\nNexus Security`,
    html:    `<p>Hi ${user.name},</p><p>Click the button below to verify your email address:</p><p><a href="${verifyUrl}" style="background:#3B82F6;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;font-family:sans-serif;display:inline-block">Verify Email</a></p><p style="color:#888;font-size:12px">This link expires in 24 hours. If you didn't create an account, ignore this email.</p>`,
  });
}

// POST /api/auth/send-verification  — resend verification email
router.post('/send-verification', requireAuth, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  if (user.email_verified) return res.json({ message: 'Email already verified' });

  await sendVerificationEmail(user);
  res.json({ message: 'Verification email sent' });
});

// GET /api/auth/verify-email?token=xxx  — confirm the token
router.get('/verify-email', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token required' });

  const hash = hashToken(token);
  const row  = db.prepare('SELECT * FROM email_verifications WHERE token_hash = ? AND used = 0').get(hash);

  if (!row)                            return res.status(400).json({ error: 'Invalid or expired link' });
  if (new Date(row.expires_at) < new Date()) return res.status(400).json({ error: 'Verification link has expired' });

  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(row.user_id);
  db.prepare('UPDATE email_verifications SET used = 1 WHERE id = ?').run(row.id);

  res.json({ message: 'Email verified successfully' });
});

module.exports = router;
module.exports.sendVerificationEmail = sendVerificationEmail;
