const express  = require('express');
const db       = require('../db/database');
const { z }    = require('zod');
const { requireAdmin } = require('../middleware/auth');

const router = express.Router();
const emailSchema = z.object({ email: z.string().email().transform(v => v.toLowerCase().trim()) });

// POST /api/newsletter
router.post('/', (req, res) => {
  const result = emailSchema.safeParse(req.body);
  if (!result.success) return res.status(400).json({ error: 'Valid email required' });

  const { email } = result.data;
  const existing = db.prepare('SELECT id, unsubscribed FROM newsletter_subscribers WHERE email = ?').get(email);

  if (existing) {
    if (!existing.unsubscribed) return res.status(409).json({ error: 'Already subscribed' });
    db.prepare('UPDATE newsletter_subscribers SET unsubscribed = 0, subscribed_at = CURRENT_TIMESTAMP WHERE email = ?').run(email);
  } else {
    db.prepare('INSERT INTO newsletter_subscribers (email) VALUES (?)').run(email);
  }
  res.json({ message: 'Subscribed! You\'ll receive our next security tip email.' });
});

// GET /api/newsletter  — admin only
router.get('/', requireAdmin, (req, res) => {
  const subs = db.prepare('SELECT * FROM newsletter_subscribers WHERE unsubscribed = 0 ORDER BY subscribed_at DESC').all();
  res.json(subs);
});

// DELETE /api/newsletter/:email  — unsubscribe
router.delete('/:email', (req, res) => {
  // Normalize to match how addresses are stored (subscribe lowercases + trims),
  // otherwise "Foo@x.com" would never match the stored "foo@x.com".
  const email = String(req.params.email || '').toLowerCase().trim();
  db.prepare('UPDATE newsletter_subscribers SET unsubscribed = 1 WHERE email = ?').run(email);
  res.json({ message: 'Unsubscribed' });
});

module.exports = router;
