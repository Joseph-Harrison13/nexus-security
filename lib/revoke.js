// Session/token revocation helpers used for incident response and account
// suspension.
//
// Access tokens are stateless JWTs, so the only way to kill one before it expires
// is to add its `jti` to revoked_tokens (requireAuth rejects revoked jtis). Every
// live access token has a session row carrying its jti, so revoking all session
// jtis + revoking refresh tokens + dropping the session rows forces a full
// re-authentication.
//
// LIMITATION: this cannot stop tokens an attacker FORGES with a leaked
// JWT_SECRET (those have fresh jtis we never issued). For a suspected secret
// compromise you must rotate JWT_SECRET — see the incident-response runbook.
const db = require('../db/database');

// Revoke a single user's outstanding access + refresh tokens. Returns the number
// of sessions cut off.
function revokeUserSessions(userId) {
  const rows = db.prepare('SELECT jti FROM sessions WHERE user_id = ? AND jti IS NOT NULL').all(userId);
  const ins  = db.prepare('INSERT OR IGNORE INTO revoked_tokens (jti) VALUES (?)');
  db.transaction(() => {
    for (const { jti } of rows) ins.run(jti);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0').run(userId);
  })();
  return rows.length;
}

// Revoke every session for every member of one organization. Returns the count.
function revokeOrgSessions(orgId) {
  const rows = db.prepare(
    'SELECT s.jti FROM sessions s JOIN users u ON s.user_id = u.id WHERE u.org_id = ? AND s.jti IS NOT NULL'
  ).all(orgId);
  const ins = db.prepare('INSERT OR IGNORE INTO revoked_tokens (jti) VALUES (?)');
  db.transaction(() => {
    for (const { jti } of rows) ins.run(jti);
    db.prepare('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE org_id = ?)').run(orgId);
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id IN (SELECT id FROM users WHERE org_id = ?) AND revoked = 0').run(orgId);
  })();
  return rows.length;
}

// The platform "panic button": revoke every session for every user. Returns the count.
function revokeAllSessions() {
  const rows = db.prepare('SELECT jti FROM sessions WHERE jti IS NOT NULL').all();
  const ins  = db.prepare('INSERT OR IGNORE INTO revoked_tokens (jti) VALUES (?)');
  db.transaction(() => {
    for (const { jti } of rows) ins.run(jti);
    db.prepare('DELETE FROM sessions').run();
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE revoked = 0').run();
  })();
  return rows.length;
}

module.exports = { revokeUserSessions, revokeOrgSessions, revokeAllSessions };
