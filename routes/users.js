const express = require('express');
const bcrypt  = require('bcrypt');
const crypto  = require('crypto');
const db      = require('../db/database');
const { requireAuth, requireAdmin, requireSuperAdmin } = require('../middleware/auth');
const validate = require('../middleware/validate');
const { schemas } = require('../lib/schemas');
const { E }  = require('../lib/errors');
const { sendMail } = require('../lib/mailer');
const { csvRow } = require('../lib/csv');
const { createNotification } = require('./notifications');
const { revokeUserSessions, revokeOrgSessions, revokeAllSessions } = require('../lib/revoke');
const { getBool, setSetting } = require('../lib/appSettings');
const { canManageUser, usersScope } = require('../lib/scope');
const limits = require('../lib/limits');

// The organization the caller belongs to, with its plan (billing/limits live here).
function callerOrg(req) {
  return db.prepare('SELECT id, name, plan FROM organizations WHERE id = ?').get(req.user.org_id)
    || { id: req.user.org_id, plan: 'Starter' };
}

const router = express.Router();
const SAFE   = 'id, email, name, role, plan, storage_used, created_at, last_login, suspended';

// A strong temporary password that satisfies the password policy (upper+lower+digit+symbol).
function randomTempPassword() {
  const U = 'ABCDEFGHJKLMNPQRSTUVWXYZ', L = 'abcdefghijkmnpqrstuvwxyz', D = '23456789', S = '!@#$%^&*';
  const pick = (set) => set[crypto.randomInt(set.length)];
  let pw = pick(U) + pick(L) + pick(D) + pick(S);
  const all = U + L + D + S;
  for (let i = 0; i < 8; i++) pw += pick(all);
  return pw.split('').sort(() => crypto.randomInt(3) - 1).join('');
}

function emailConfigured() {
  return !!process.env.EMAIL_USER && process.env.EMAIL_USER !== 'your@email.com' && !!process.env.EMAIL_PASS;
}

// Issue a single-use "set your password" link (7-day expiry), reusing the
// password-reset token flow. Any prior unused token for the user is invalidated.
function createInviteLink(userId) {
  const rawToken  = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('UPDATE password_reset_tokens SET used = 1 WHERE user_id = ?').run(userId);
  db.prepare('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)').run(userId, tokenHash, expiresAt);
  const base = process.env.SITE_URL || `http://localhost:${process.env.PORT || 3000}`;
  return `${base}/pages/reset-password.html?token=${rawToken}`;
}

function sendInviteEmail(email, name, link) {
  return sendMail({
    to: email,
    subject: "You've been invited to Nexus Security",
    text: `Hi ${name},\n\nYour Nexus Security account is ready. Set your password to get started:\n\n${link}\n\nThis link expires in 7 days.\n\n— Nexus Security Team`,
    html: `<div style="font-family:sans-serif;max-width:500px;margin:0 auto"><h2 style="color:#1a1a1a">Welcome to Nexus Security</h2><p>Hi ${name},</p><p>Your account is ready. Click below to set your password and sign in:</p><p><a href="${link}" style="background:#14b8a6;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;display:inline-block">Set Your Password</a></p><p style="color:#888;font-size:12px;margin-top:20px">This link expires in 7 days. If you didn't expect this, you can ignore this email.</p></div>`,
  });
}

// Parse a simple CSV of users. Accepts an optional header row (name,email,role,plan
// in any order); otherwise assumes that column order.
function parseUsersCsv(text) {
  const lines = String(text).split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (!lines.length) return [];
  let header = null, start = 0;
  if (lines[0].toLowerCase().includes('email')) {
    header = lines[0].split(',').map((h) => h.trim().toLowerCase());
    start = 1;
  }
  const out = [];
  for (let i = start; i < lines.length; i++) {
    const cells = lines[i].split(',').map((c) => c.trim());
    if (header) {
      const row = {};
      header.forEach((h, idx) => { row[h] = cells[idx] || ''; });
      out.push({ name: row.name, email: row.email, role: row.role, plan: row.plan });
    } else {
      out.push({ name: cells[0], email: cells[1], role: cells[2], plan: cells[3] });
    }
  }
  return out;
}

function parsePage(query) {
  const page  = Math.max(1,   parseInt(query.page  || '1',  10));
  const limit = Math.min(100, Math.max(1, parseInt(query.limit || '20', 10)));
  return { page, limit, offset: (page - 1) * limit };
}

// GET /api/users
router.get('/', requireAuth, (req, res) => {
  const { page, limit, offset } = parsePage(req.query);
  const scope = usersScope(req); // SuperAdmin: all · Admin: own org · User: self

  const total = db.prepare(`SELECT COUNT(*) AS n FROM users WHERE ${scope.sql}`).get(...scope.params).n;
  const data  = db.prepare(`SELECT ${SAFE} FROM users WHERE ${scope.sql} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .all(...scope.params, limit, offset);
  const totalPages = Math.ceil(total / limit);
  res.json({ data, pagination: { page, limit, total, totalPages, hasNext: page < totalPages, hasPrev: page > 1 } });
});

// POST /api/users  — admin only. Creates a member of the admin's OWN organization.
router.post('/', requireAdmin, validate(schemas.createUser), async (req, res) => {
  const { email, password, name, role, plan } = req.body;
  const org = callerOrg(req);

  // Seat limit is per-organization, counting that org's members.
  const seats = limits.effectiveSeatLimit(org.plan);
  const userCount = db.prepare('SELECT COUNT(*) AS n FROM users WHERE org_id = ?').get(org.id).n;
  if (userCount >= seats) {
    return E.forbidden(res, `Your plan allows up to ${seats} users. Upgrade your plan to add more.`);
  }

  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) {
    return E.conflict(res, 'A user with that email already exists');
  }

  // An Org Admin can only create 'User' or 'Admin' within their org — never a
  // platform SuperAdmin. New members inherit the organization's plan.
  const newRole = (req.user.role === 'SuperAdmin') ? (role || 'User')
    : (role === 'Admin' ? 'Admin' : 'User');
  const passwordHash = await bcrypt.hash(password, 12);
  const result = db.prepare(`INSERT INTO users (email, password_hash, name, role, plan, org_id) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(email, passwordHash, name, newRole, org.plan, org.id);

  const newUserId = result.lastInsertRowid;
  db.prepare('INSERT INTO activity_log (user_id, action, detail) VALUES (?, ?, ?)')
    .run(req.user.sub, 'user_created', `Created account for ${email}`);

  // Welcome notification for new user
  createNotification(newUserId, 'welcome', '🎉', `Welcome to Nexus Security, ${name}! Your account is ready.`);
  createNotification(newUserId, 'security_tip', '🔐', 'Tip: Enable Two-Factor Authentication in Settings to secure your account.');

  // Send welcome email
  sendMail({
    to: email,
    subject: 'Welcome to Nexus Security',
    text: `Hi ${name},\n\nYour Nexus Security account is ready.\n\nEmail: ${email}\nPlan: ${plan}\n\nLog in at: ${process.env.SITE_URL || 'https://localhost:3443'}/pages/login.html\n\nNexus Security Team`,
    html: `<div style="font-family:sans-serif;max-width:500px;margin:0 auto"><h2 style="color:#1a1a1a">Welcome to Nexus Security</h2><p>Hi ${name},</p><p>Your account has been created and your data is already being protected.</p><table style="border-collapse:collapse;margin:16px 0"><tr><td style="padding:6px 12px 6px 0;color:#888">Email:</td><td style="padding:6px 0;font-weight:500">${email}</td></tr><tr><td style="padding:6px 12px 6px 0;color:#888">Plan:</td><td style="padding:6px 0;font-weight:500">${plan}</td></tr></table><p><a href="${process.env.SITE_URL || 'https://localhost:3443'}/pages/login.html" style="background:#3B82F6;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;display:inline-block">Log In to Your Dashboard</a></p><p style="color:#888;font-size:12px;margin-top:24px">If you didn't expect this email, please contact us immediately.</p></div>`,
  }).catch(() => {}); // non-blocking

  res.status(201).json(db.prepare(`SELECT ${SAFE} FROM users WHERE id = ?`).get(newUserId));
});

// PUT /api/users/:id  — admin or own account
router.put('/:id', requireAuth, validate(schemas.updateUser), async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  const target   = db.prepare('SELECT id, org_id FROM users WHERE id = ?').get(targetId);
  if (!target) return E.notFound(res, 'User not found');
  const elevated = req.user.role === 'Admin' || req.user.role === 'SuperAdmin';
  // Self-edit is always allowed; admins may only edit users in their own org.
  if (req.user.sub !== targetId && !canManageUser(req, target)) return E.forbidden(res, 'Forbidden');

  const { name, role, plan, password } = req.body;
  const updates = [], values = [];

  if (name)     { updates.push('name = ?');          values.push(name); }
  if (password) { updates.push('password_hash = ?'); values.push(await bcrypt.hash(password, 12)); }
  if (elevated && req.user.sub !== targetId) {
    // Org Admins can't mint a SuperAdmin.
    if (role) { updates.push('role = ?'); values.push(req.user.role === 'SuperAdmin' ? role : (role === 'Admin' ? 'Admin' : 'User')); }
    if (plan) { updates.push('plan = ?'); values.push(plan); }
  }

  if (!updates.length) return E.badRequest(res, 'Nothing to update');
  values.push(targetId);
  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values);

  // If an admin changed the user's role, revoke their existing tokens so the new
  // privilege level takes effect immediately rather than after the token expires.
  if (elevated && role) {
    db.prepare('SELECT jti FROM sessions WHERE user_id = ?').all(targetId)
      .forEach(s => db.prepare('INSERT OR IGNORE INTO revoked_tokens (jti) VALUES (?)').run(s.jti));
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(targetId);
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').run(targetId);
  }

  db.prepare('INSERT INTO activity_log (user_id, action, detail) VALUES (?, ?, ?)')
    .run(req.user.sub, 'user_updated', `Updated user id=${targetId}`);

  res.json(db.prepare(`SELECT ${SAFE} FROM users WHERE id = ?`).get(targetId));
});

// DELETE /api/users/:id  — admin only
router.delete('/:id', requireAdmin, (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (targetId === req.user.sub) return E.badRequest(res, 'You cannot delete your own account');

  const user = db.prepare('SELECT email, org_id FROM users WHERE id = ?').get(targetId);
  if (!canManageUser(req, user)) return E.notFound(res, 'User not found');

  // Revoke the user's live tokens first — the row cascade drops session rows, but
  // signed JWTs stay valid until expiry unless their jti is revoked.
  revokeUserSessions(targetId);
  db.prepare('DELETE FROM users WHERE id = ?').run(targetId);
  db.prepare('INSERT INTO activity_log (user_id, action, detail) VALUES (?, ?, ?)')
    .run(req.user.sub, 'user_deleted', `Deleted ${user.email}`);

  res.json({ message: `User ${user.email} deleted` });
});

// POST /api/users/:id/suspend  — admin only. Locks an account out immediately
// (blocks login, cuts live sessions) without destroying it or its data.
router.post('/:id/suspend', requireAdmin, (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (targetId === req.user.sub) return E.badRequest(res, 'You cannot suspend your own account');

  const user = db.prepare('SELECT email, suspended, org_id FROM users WHERE id = ?').get(targetId);
  if (!canManageUser(req, user)) return E.notFound(res, 'User not found');

  db.prepare('UPDATE users SET suspended = 1 WHERE id = ?').run(targetId);
  const cut = revokeUserSessions(targetId);
  db.prepare('INSERT INTO activity_log (user_id, action, detail) VALUES (?, ?, ?)')
    .run(req.user.sub, 'user_suspended', `Suspended ${user.email} (${cut} session${cut !== 1 ? 's' : ''} revoked)`);

  res.json({ message: `User ${user.email} suspended`, sessionsRevoked: cut });
});

// POST /api/users/:id/unsuspend  — admin only. Restores login; the user must
// sign in again (with 2FA) to get a fresh session.
router.post('/:id/unsuspend', requireAdmin, (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  const user = db.prepare('SELECT email, org_id FROM users WHERE id = ?').get(targetId);
  if (!canManageUser(req, user)) return E.notFound(res, 'User not found');

  db.prepare('UPDATE users SET suspended = 0 WHERE id = ?').run(targetId);
  db.prepare('INSERT INTO activity_log (user_id, action, detail) VALUES (?, ?, ?)')
    .run(req.user.sub, 'user_unsuspended', `Reinstated ${user.email}`);

  res.json({ message: `User ${user.email} reinstated` });
});

// POST /api/users/:id/force-password-reset  — admin only. The account keeps its
// data but must set a new password (via the normal reset flow) before it can be
// used again; its live sessions are cut immediately.
router.post('/:id/force-password-reset', requireAdmin, (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  const user = db.prepare('SELECT email, org_id FROM users WHERE id = ?').get(targetId);
  if (!canManageUser(req, user)) return E.notFound(res, 'User not found');

  db.prepare('UPDATE users SET force_password_reset = 1 WHERE id = ?').run(targetId);
  revokeUserSessions(targetId);
  db.prepare('INSERT INTO activity_log (user_id, action, detail) VALUES (?, ?, ?)')
    .run(req.user.sub, 'force_password_reset', `Forced password reset for ${user.email}`);

  res.json({ message: `${user.email} must reset their password before next sign-in` });
});

// POST /api/users/force-password-reset-all  — mass credential invalidation.
// Org Admin resets their OWN organization; SuperAdmin resets the whole platform.
// Excludes the caller so you don't lock yourself out mid-response.
router.post('/force-password-reset-all', requireAdmin, (req, res) => {
  let info, cut;
  if (req.user.role === 'SuperAdmin') {
    info = db.prepare('UPDATE users SET force_password_reset = 1 WHERE id != ?').run(req.user.sub);
    cut  = revokeAllSessions();
  } else {
    info = db.prepare('UPDATE users SET force_password_reset = 1 WHERE org_id = ? AND id != ?').run(req.user.org_id, req.user.sub);
    cut  = revokeOrgSessions(req.user.org_id);
  }
  db.prepare('INSERT INTO activity_log (user_id, action, detail) VALUES (?, ?, ?)')
    .run(req.user.sub, 'force_password_reset_all', `Forced reset for ${info.changes} accounts`);
  res.json({ message: `${info.changes} accounts must reset their password`, sessionsRevoked: cut });
});

// GET/POST /api/users/maintenance  — PLATFORM owner only. Walls the whole API
// off (503) for everyone but admins. This is a platform-wide switch, so it is
// restricted to the SuperAdmin, not per-org admins.
router.get('/maintenance', requireSuperAdmin, (req, res) => {
  res.json({ enabled: getBool('maintenance_mode') });
});
router.post('/maintenance', requireSuperAdmin, express.json(), (req, res) => {
  const enabled = !!req.body.enabled;
  setSetting('maintenance_mode', enabled ? '1' : '0');
  db.prepare('INSERT INTO activity_log (user_id, action, detail) VALUES (?, ?, ?)')
    .run(req.user.sub, 'maintenance_mode', `Maintenance mode ${enabled ? 'ENABLED' : 'disabled'}`);
  res.json({ enabled, message: `Maintenance mode ${enabled ? 'enabled' : 'disabled'}` });
});

// POST /api/users/revoke-all-sessions  — the "panic button". Org Admin signs out
// their OWN organization; SuperAdmin signs out the entire platform. Cannot stop
// tokens forged with a leaked JWT_SECRET — rotate the secret for that.
router.post('/revoke-all-sessions', requireAdmin, (req, res) => {
  const count = req.user.role === 'SuperAdmin' ? revokeAllSessions() : revokeOrgSessions(req.user.org_id);
  const scope = req.user.role === 'SuperAdmin' ? 'platform-wide' : 'organization';
  db.prepare('INSERT INTO activity_log (user_id, action, detail) VALUES (?, ?, ?)')
    .run(req.user.sub, 'sessions_revoked_all', `Session revocation (${scope}, ${count} sessions)`);
  res.json({ message: `All sessions revoked — affected users must sign in again`, sessionsRevoked: count });
});

// GET /api/users/export/csv  — admin only
router.get('/export/csv', requireAdmin, (req, res) => {
  const scope = usersScope(req);
  const users = db.prepare(`SELECT ${SAFE} FROM users WHERE ${scope.sql} ORDER BY created_at DESC`).all(...scope.params);
  const header = 'id,email,name,role,plan,storage_used_bytes,created_at,last_login\n';
  const rows   = users.map(u =>
    csvRow([u.id, u.email, u.name || '', u.role, u.plan, u.storage_used, u.created_at || '', u.last_login || ''])
  ).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="users.csv"');
  res.send(header + rows);
});

// POST /api/users/import — admin bulk-creates accounts from CSV or a users array.
// Returns the created accounts (with one-time temp passwords for the admin to share),
// plus any skipped duplicates and errors. Seat limit is respected as it goes.
router.post('/import', requireAdmin, express.json({ limit: '1mb' }), async (req, res) => {
  let rows;
  if (Array.isArray(req.body.users)) rows = req.body.users;
  else if (typeof req.body.csv === 'string') rows = parseUsersCsv(req.body.csv);
  else return E.badRequest(res, 'Provide a CSV string (csv) or an array (users).');

  if (!rows.length) return E.badRequest(res, 'No user rows found to import.');
  if (rows.length > 500) return E.badRequest(res, 'Please import 500 users or fewer at a time.');

  const org         = callerOrg(req);
  const seats       = limits.effectiveSeatLimit(org.plan);
  const validRoles  = new Set(['User', 'Admin']);
  const emailRe     = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  let count         = db.prepare('SELECT COUNT(*) AS n FROM users WHERE org_id = ?').get(org.id).n;

  const canEmail = emailConfigured();
  const created = [], skipped = [], errors = [];
  for (const row of rows) {
    const email = String(row.email || '').trim().toLowerCase();
    const name  = String(row.name || '').trim();
    const role  = validRoles.has(row.role) ? row.role : 'User';
    const plan  = org.plan; // members inherit the organization's plan

    if (!emailRe.test(email)) { errors.push({ email: row.email || '(blank)', reason: 'Invalid email' }); continue; }
    if (!name)                { errors.push({ email, reason: 'Missing name' }); continue; }
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) { skipped.push({ email, reason: 'Already exists' }); continue; }
    if (count >= seats)       { errors.push({ email, reason: `Seat limit (${seats}) reached` }); continue; }

    // Create with an unguessable placeholder hash — the user sets their real
    // password via the invite link, so no plaintext password is ever exposed.
    const hash   = await bcrypt.hash(randomTempPassword(), 12);
    const result = db.prepare('INSERT INTO users (email, password_hash, name, role, plan, org_id) VALUES (?, ?, ?, ?, ?, ?)')
      .run(email, hash, name, role, plan, org.id);
    count++;

    const inviteLink = createInviteLink(result.lastInsertRowid);
    if (canEmail) {
      sendInviteEmail(email, name, inviteLink).catch(() => {});
      created.push({ email, name });
    } else {
      // No email configured — hand the link back so the admin can share it.
      created.push({ email, name, inviteLink });
    }
    db.prepare('INSERT INTO activity_log (user_id, action, detail) VALUES (?, ?, ?)')
      .run(req.user.sub, 'user_imported', `Bulk-imported ${email} (invite sent)`);
    createNotification(result.lastInsertRowid, 'welcome', '🎉', `Welcome to Nexus Security, ${name}! Check your email to set your password.`);
  }

  res.json({
    createdCount: created.length,
    skippedCount: skipped.length,
    errorCount:   errors.length,
    invitesEmailed: canEmail,
    created, skipped, errors,
  });
});

module.exports = router;
