const express = require('express');
const db      = require('../db/database');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// GET /api/sessions — list all active sessions for the current user
router.get('/', requireAuth, (req, res) => {
  const now      = new Date().toISOString();
  const sessions = db.prepare(`
    SELECT id, ip, user_agent, created_at, last_used, expires_at,
           (jti = ?) AS is_current
    FROM sessions
    WHERE user_id = ? AND expires_at > ?
    ORDER BY last_used DESC
  `).all(req.user.jti, req.user.sub, now);

  res.json(sessions);
});

// DELETE /api/sessions/:id — revoke a specific session
router.delete('/:id', requireAuth, (req, res) => {
  const session = db.prepare('SELECT * FROM sessions WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.sub);

  if (!session) return res.status(404).json({ error: 'Session not found' });

  db.prepare('INSERT OR IGNORE INTO revoked_tokens (jti) VALUES (?)').run(session.jti);
  // Also revoke the refresh token tied to this session — otherwise it could mint
  // a fresh access token via /refresh, making the revocation ineffective.
  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE session_id = ?').run(session.id);
  db.prepare('DELETE FROM sessions WHERE id = ?').run(session.id);

  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.sub, 'session_revoked', `Revoked session from ${session.ip || 'unknown IP'}`, req.ip);

  res.json({ message: 'Session revoked' });
});

// DELETE /api/sessions — revoke ALL other sessions (keep current)
router.delete('/', requireAuth, (req, res) => {
  const others = db.prepare('SELECT id, jti FROM sessions WHERE user_id = ? AND jti != ?')
    .all(req.user.sub, req.user.jti);

  others.forEach(s => {
    db.prepare('INSERT OR IGNORE INTO revoked_tokens (jti) VALUES (?)').run(s.jti);
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE session_id = ?').run(s.id);
  });
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND jti != ?').run(req.user.sub, req.user.jti);

  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.sub, 'sessions_revoked_all', `Revoked ${others.length} other session(s)`, req.ip);

  res.json({ message: `${others.length} other session(s) revoked` });
});

module.exports = router;
