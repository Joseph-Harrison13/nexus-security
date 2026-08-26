const request = require('supertest');
const app = require('../server');
const db = require('../db/database');

const STRONG = 'Str0ng!Pass1';

// Wipe all data between tests so each test starts clean (the DB is in-memory and
// shared within a test file).
function resetDb() {
  const tables = [
    'users', 'organizations', 'files', 'contact_submissions', 'activity_log', 'revoked_tokens',
    'sessions', 'password_reset_tokens', 'refresh_tokens', 'backup_codes',
    'notifications', 'newsletter_subscribers', 'email_verifications', 'push_subscriptions',
    'folders', 'login_codes', 'file_shares', 'app_settings',
  ];
  for (const t of tables) {
    try { db.prepare(`DELETE FROM ${t}`).run(); } catch { /* table may not exist */ }
  }
}

// Register a user, complete the dev 2FA flow, and return an access token.
//
// Signup now creates a NEW organization with the signer as its Org Admin. For
// tests we normalize:
//   • role defaults to 'User' (plain member) — pass overrides.role for 'Admin'
//     or 'SuperAdmin'.
//   • overrides.orgId puts the user in an EXISTING org (for same-org tests)
//     instead of their own fresh one.
// Returns { email, token, user, id, orgId }.
async function registerAndLogin(overrides = {}) {
  const email = overrides.email || `user_${Math.random().toString(36).slice(2)}@test.com`;
  await request(app).post('/api/auth/register')
    .send({ firstName: 'T', lastName: 'U', businessName: 'Biz', email, password: STRONG });

  const role = overrides.role || 'User';
  db.prepare('UPDATE users SET role = ? WHERE email = ?').run(role, email);
  if (overrides.orgId) db.prepare('UPDATE users SET org_id = ? WHERE email = ?').run(overrides.orgId, email);
  // Two-factor auth is mandatory (see requireAuth); flip the flag so test users
  // can exercise data routes via the demo-code login path. noTotp opts out.
  if (!overrides.noTotp) db.prepare('UPDATE users SET totp_enabled = 1 WHERE email = ?').run(email);

  const login = await request(app).post('/api/auth/login').send({ email, password: STRONG });
  const verify = await request(app).post('/api/auth/verify-2fa')
    .send({ tempToken: login.body.tempToken, code: process.env.DEMO_2FA_CODE || '482719' });

  const row = db.prepare('SELECT id, org_id FROM users WHERE email = ?').get(email);
  return { email, token: verify.body.token, user: verify.body.user, id: row && row.id, orgId: row && row.org_id };
}

// Upload a file; pass extraFields (e.g. { folderId }) as multipart fields.
async function uploadFile(token, name = 'note.txt', content = 'hello world', extraFields = {}) {
  const req = request(app).post('/api/files/upload').set('Authorization', `Bearer ${token}`);
  for (const [k, v] of Object.entries(extraFields)) req.field(k, String(v));
  return req.attach('file', Buffer.from(content), name);
}

module.exports = { app, db, request, resetDb, registerAndLogin, uploadFile, STRONG };
