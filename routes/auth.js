const express   = require('express');
const bcrypt    = require('bcrypt');
const jwt       = require('jsonwebtoken');
const crypto    = require('crypto');
const speakeasy = require('speakeasy');
const qrcode    = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const db        = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const validate  = require('../middleware/validate');
const { schemas } = require('../lib/schemas');
const { E, sendError } = require('../lib/errors');
const { alertNewIPLogin, alertNewLocationCode, alertAccountLocked, alertPasswordResetRequested } = require('../lib/alerts');
const { sendVerificationEmail } = require('./verify-email');
const { driver: storage } = require('../lib/storage');
const { isBreached } = require('../lib/breachCheck');
const { getBool } = require('../lib/appSettings');

const router = express.Router();

const MAX_ATTEMPTS    = 5;
const LOCKOUT_MINUTES = 30;
const MAX_2FA_TRIES   = 5;

// In-memory counter for 2FA brute-force protection (keyed by tempToken JTI)
const twoFaAttempts = new Map();

// ── Helpers ─────────────────────────────────────────────────

function signAccess(payload) {
  const jti = uuidv4();
  const token = jwt.sign(
    { jti, ...payload },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
  );
  return { token, jti };
}

function signTemp(payload) {
  return jwt.sign(
    { jti: uuidv4(), ...payload },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_2FA_EXPIRES_IN || '5m' }
  );
}

function setRefreshCookie(res, token) {
  res.cookie('refreshToken', token, {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge:   30 * 24 * 60 * 60 * 1000, // 30 days
    path:     '/api/auth',
  });
}

// The access token lives in an httpOnly cookie so client-side JavaScript can
// never read it — even a successful XSS can't exfiltrate the session. Browsers
// send it automatically on same-origin API calls; sameSite=strict blocks it
// from being sent on cross-site requests (CSRF protection).
function setAccessCookie(res, token) {
  res.cookie('access_token', token, {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge:   60 * 60 * 1000, // 1h — matches access-token expiry
    path:     '/',
  });
}

function storeRefreshToken(userId, rawToken, sessionId) {
  const hash      = crypto.createHash('sha256').update(rawToken).digest('hex');
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO refresh_tokens (user_id, token_hash, session_id, expires_at) VALUES (?, ?, ?, ?)')
    .run(userId, hash, sessionId || null, expiresAt);
  return hash;
}

function createSession(userId, jti, ip, userAgent, expiresAt) {
  const id = uuidv4();
  db.prepare('INSERT INTO sessions (id, user_id, jti, ip, user_agent, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, userId, jti, ip, userAgent, expiresAt);
  return id;
}

function generateBackupCodes() {
  const raw = [];
  for (let i = 0; i < 8; i++) {
    const part1 = crypto.randomBytes(2).toString('hex').toUpperCase();
    const part2 = crypto.randomBytes(2).toString('hex').toUpperCase();
    raw.push(`${part1}-${part2}`);
  }
  return raw;
}

function hashBackupCode(code) {
  return crypto.createHash('sha256').update(code.toUpperCase()).digest('hex');
}

function log(userId, action, detail, ip) {
  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)').run(userId, action, detail, ip);
}

function isLockedOut(user) {
  return user.locked_until && new Date(user.locked_until) > new Date();
}

function recordFailedAttempt(user, ip) {
  const count = (user.failed_attempts || 0) + 1;
  if (count >= MAX_ATTEMPTS) {
    const until = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000).toISOString();
    db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?').run(count, until, user.id);
    alertAccountLocked(user, ip).catch(() => {});
    return { locked: true };
  }
  db.prepare('UPDATE users SET failed_attempts = ? WHERE id = ?').run(count, user.id);
  return { locked: false, remaining: MAX_ATTEMPTS - count };
}

function clearFailedAttempts(userId) {
  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(userId);
}

function isKnownIP(user, ip) {
  try { return JSON.parse(user.known_ips || '[]').includes(ip); } catch { return false; }
}

// Is outbound email actually wired up? If not, we can't deliver a location code,
// so we must not gate login on one (that would lock the user out).
function emailConfigured() {
  return !!process.env.EMAIL_USER && process.env.EMAIL_USER !== 'your@email.com' && !!process.env.EMAIL_PASS;
}

// Generate, store (hashed), and return a 6-digit one-time code for a new-location
// login. Any earlier unused codes for the user are invalidated first.
function createLocationCode(user, ip) {
  const code     = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = crypto.createHash('sha256').update(code).digest('hex');
  const expires  = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  db.prepare('UPDATE login_codes SET used = 1 WHERE user_id = ? AND used = 0').run(user.id);
  db.prepare('INSERT INTO login_codes (user_id, code_hash, ip, expires_at) VALUES (?, ?, ?, ?)').run(user.id, codeHash, ip, expires);
  return code;
}

function maskEmail(email) {
  const [name, domain] = String(email).split('@');
  if (!domain) return email;
  const head = name.length <= 2 ? name[0] : name.slice(0, 2);
  return `${head}${'*'.repeat(Math.max(1, name.length - 2))}@${domain}`;
}

function recordKnownIP(user, ip) {
  try {
    const known = JSON.parse(user.known_ips || '[]');
    if (!known.includes(ip)) {
      known.push(ip);
      if (known.length > 20) known.shift();
      db.prepare('UPDATE users SET known_ips = ? WHERE id = ?').run(JSON.stringify(known), user.id);
    }
  } catch { /* ignore */ }
}

// Finalize a successful authentication: record the login, issue an access token +
// session, set the refresh cookie, and send the standard auth response. Shared by
// the 2FA verification path and the (production) password-only path for accounts
// without an authenticator app.
function completeLogin(req, res, user, { usedBackupCode = false } = {}) {
  if (!isKnownIP(user, req.ip)) {
    alertNewIPLogin(user, req.ip, req.headers['user-agent']).catch(() => {});
    log(user.id, 'login_new_ip', `New IP: ${req.ip}`, req.ip);
  }
  recordKnownIP(user, req.ip);
  clearFailedAttempts(user.id);
  db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
  if (usedBackupCode) log(user.id, 'backup_code_used', 'Signed in with a backup code', req.ip);
  log(user.id, 'login', 'Successful login', req.ip);

  const expiresAt      = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1h
  const { token, jti } = signAccess({ sub: user.id, email: user.email, name: user.name, role: user.role, plan: user.plan, org_id: user.org_id });
  const sessionId      = createSession(user.id, jti, req.ip, req.headers['user-agent'], expiresAt);

  const rawRefresh = crypto.randomBytes(40).toString('hex');
  storeRefreshToken(user.id, rawRefresh, sessionId);
  setRefreshCookie(res, rawRefresh);
  setAccessCookie(res, token);

  // Two-factor authentication is mandatory for every account. We issue a session
  // so the user can enrol, but flag it so the UI pushes them straight to setup —
  // and requireAuth blocks all data routes until an authenticator app is on.
  const mustEnableTotp = !user.totp_enabled;

  res.json({
    token,
    mustEnableTotp,
    user: { id: user.id, email: user.email, name: user.name, role: user.role, plan: user.plan, org_id: user.org_id },
  });
}

// ─────────────────────────────────────────────────
// POST /api/auth/register
// ─────────────────────────────────────────────────
router.post('/register', validate(schemas.register), async (req, res) => {
  const { firstName, lastName, businessName, email, password } = req.body;

  // Reject passwords known to have appeared in data breaches (fails open).
  const breaches = await isBreached(password);
  if (breaches) {
    return E.badRequest(res, `This password has appeared in ${breaches.toLocaleString()} known data breaches. Please choose a different one.`, ['BREACHED_PASSWORD']);
  }

  // Hash unconditionally so response timing doesn't reveal whether the email
  // already exists, and return the same message either way (no account enumeration).
  const passwordHash = await bcrypt.hash(password, 12);
  const SAFE_RESPONSE = { message: 'Account created. Check your email to verify your address, then sign in.' };

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(201).json(SAFE_RESPONSE);

  const name = `${firstName} ${lastName}`;

  // Self-serve signup creates a new organization; the signer becomes its Admin.
  // The designated platform owner (PLATFORM_ADMIN_EMAIL) is minted as SuperAdmin.
  const isPlatformOwner = process.env.PLATFORM_ADMIN_EMAIL &&
    email.toLowerCase() === process.env.PLATFORM_ADMIN_EMAIL.toLowerCase();
  const role      = isPlatformOwner ? 'SuperAdmin' : 'Admin';
  const plan      = ['Starter', 'Growth', 'Pro'].includes(req.body.plan) ? req.body.plan : 'Starter';
  // Every new organization starts on a 21-day free trial of its chosen plan.
  const trialEnds = new Date(Date.now() + 21 * 24 * 60 * 60 * 1000).toISOString();
  const orgId = db.prepare(
    "INSERT INTO organizations (name, plan, subscription_status, trial_ends_at) VALUES (?, ?, 'trialing', ?)"
  ).run(businessName, plan, trialEnds).lastInsertRowid;
  const result = db.prepare(
    'INSERT INTO users (email, password_hash, name, role, plan, email_verified, org_id) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(email, passwordHash, name, role, plan, 0, orgId);

  log(result.lastInsertRowid, 'register', `New account — ${businessName}`, req.ip);

  // Send the verification email (non-blocking — account is usable but unverified).
  sendVerificationEmail({ id: result.lastInsertRowid, name, email }).catch(() => {});

  res.status(201).json(SAFE_RESPONSE);
});

// ─────────────────────────────────────────────────
// POST /api/auth/login
// ─────────────────────────────────────────────────
router.post('/login', validate(schemas.login), async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user) return E.unauthorized(res, 'Invalid email or password');

  if (isLockedOut(user)) {
    const at = new Date(user.locked_until).toLocaleTimeString();
    return E.locked(res, `Account locked — try again after ${at}`);
  }

  // A previous lock has expired — clear the stale counter so the user gets a full
  // set of attempts again, instead of one wrong password re-locking immediately.
  if (user.locked_until && new Date(user.locked_until) <= new Date()) {
    clearFailedAttempts(user.id);
    user.failed_attempts = 0;
    user.locked_until    = null;
  }

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    const result = recordFailedAttempt(user, req.ip);
    log(user.id, 'login_failed', `Wrong password (attempt ${(user.failed_attempts || 0) + 1})`, req.ip);
    if (result.locked) {
      return E.locked(res, `Account locked after ${MAX_ATTEMPTS} failed attempts. Try again in ${LOCKOUT_MINUTES} minutes.`);
    }
    return E.unauthorized(res, `Invalid email or password. ${result.remaining} attempt${result.remaining !== 1 ? 's' : ''} remaining.`);
  }

  // Suspended accounts can authenticate their password but go no further.
  if (user.suspended) {
    log(user.id, 'login_suspended', 'Login blocked — account suspended', req.ip);
    return E.forbidden(res, 'This account has been suspended. Please contact support.');
  }

  // Email verification gate. Only enforced when email is actually deliverable —
  // otherwise a user could never verify and would be locked out. This ties first
  // access to control of the inbox, closing the window where a stolen password
  // alone could enrol 2FA on a brand-new account.
  if (emailConfigured() && !user.email_verified) {
    sendVerificationEmail({ id: user.id, name: user.name, email: user.email }).catch(() => {});
    log(user.id, 'login_unverified', 'Login blocked — email not verified', req.ip);
    return E.forbidden(res, 'Please verify your email address first — we just re-sent the verification link to your inbox.');
  }

  // Forced password reset (admin-initiated, e.g. suspected credential compromise).
  // The password is correct but the account must set a new one via the reset flow.
  if (user.force_password_reset) {
    log(user.id, 'login_force_reset', 'Login blocked — password reset required', req.ip);
    return sendError(res, 403,
      'For your security, you must set a new password before signing in. Use the "Forgot password?" link to continue.',
      'PASSWORD_RESET_REQUIRED');
  }

  // Email two-factor authentication. For accounts without an authenticator app
  // (which already have a second factor), we email a one-time code before the login
  // completes when EITHER:
  //   • email 2FA is enabled (the default) — every login, or
  //   • it's disabled, but this is a sign-in from a new location (safety net).
  // Gated on email actually being deliverable so we never lock anyone out, and so
  // the demo-2FA flow is untouched in environments without email configured.
  // In non-production, the code is also surfaced via demoHint so it stays testable.
  const emailTwoFaOn = user.email_2fa !== 0;       // default ON (column defaults to 1)
  const newLocation  = !isKnownIP(user, req.ip);
  if (!user.totp_enabled && emailConfigured() && (emailTwoFaOn || newLocation)) {
    const code      = createLocationCode(user, req.ip);
    const tempToken = signTemp({ sub: user.id, email: user.email, pendingLocation: true });
    alertNewLocationCode(user, code, req.ip).catch(() => {});
    const reason = newLocation ? 'new_location' : 'email_2fa';
    log(user.id, 'login_email_2fa', `Email code sent (${reason}) for IP ${req.ip}`, req.ip);
    const response = { needsLocationVerification: true, reason, tempToken, email: maskEmail(user.email) };
    if (process.env.NODE_ENV !== 'production') response.demoHint = `Demo code: ${code}`;
    return res.json(response);
  }

  // Accounts without an authenticator app have no real second factor. In production
  // we complete the login here (password-only) instead of accepting a static code.
  // In development we still issue a temp token so the demo 2FA flow can be exercised.
  if (!user.totp_enabled && process.env.NODE_ENV === 'production') {
    return completeLogin(req, res, user);
  }

  const tempToken = signTemp({ sub: user.id, email: user.email, pendingTwoFactor: true });
  const response  = { needsTwoFactor: true, tempToken, totpEnabled: !!user.totp_enabled };
  if (process.env.NODE_ENV !== 'production') {
    response.demoHint = user.totp_enabled
      ? 'Use your authenticator app for the 6-digit code'
      : `Demo 2FA code: ${process.env.DEMO_2FA_CODE || '482719'}`;
  }
  res.json(response);
});

// ─────────────────────────────────────────────────
// POST /api/auth/verify-2fa
// ─────────────────────────────────────────────────
router.post('/verify-2fa', validate(schemas.verify2fa), (req, res) => {
  const { tempToken, code } = req.body;

  let payload;
  try { payload = jwt.verify(tempToken, process.env.JWT_SECRET); }
  catch { return E.unauthorized(res, 'Session expired — please log in again'); }

  if (!payload.pendingTwoFactor) return E.badRequest(res, 'Invalid token type');

  // 2FA brute-force protection
  const tries = (twoFaAttempts.get(payload.jti) || 0) + 1;
  if (tries > MAX_2FA_TRIES) {
    db.prepare('INSERT OR IGNORE INTO revoked_tokens (jti) VALUES (?)').run(payload.jti);
    twoFaAttempts.delete(payload.jti);
    return E.tooMany(res, 'Too many incorrect codes — please log in again');
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.sub);
  if (!user) return E.unauthorized(res, 'User not found');

  // Verify code — TOTP, backup code, or demo static code
  let valid;
  let usedBackupCode = false;

  if (user.totp_enabled && user.totp_secret) {
    valid = speakeasy.totp.verify({ secret: user.totp_secret, encoding: 'base32', token: code.trim(), window: 1 });

    // Fallback: check backup codes
    if (!valid) {
      const codeHash = hashBackupCode(code.trim());
      const backup   = db.prepare('SELECT * FROM backup_codes WHERE user_id = ? AND code_hash = ? AND used = 0').get(user.id, codeHash);
      if (backup) {
        db.prepare('UPDATE backup_codes SET used = 1, used_at = CURRENT_TIMESTAMP WHERE id = ?').run(backup.id);
        valid = true;
        usedBackupCode = true;
      }
    }
  } else {
    // Static demo code — development only; never a valid factor in production.
    valid = process.env.NODE_ENV !== 'production'
      && code.trim() === (process.env.DEMO_2FA_CODE || '482719');
  }

  if (!valid) {
    twoFaAttempts.set(payload.jti, tries);
    log(user.id, '2fa_failed', `Wrong code (attempt ${tries})`, req.ip);
    const left = MAX_2FA_TRIES - tries;
    return E.unauthorized(res, left > 0
      ? `Incorrect code — ${left} attempt${left !== 1 ? 's' : ''} remaining`
      : 'Too many incorrect codes — please log in again');
  }

  // Success — clean up the temp token, then finalize the login
  twoFaAttempts.delete(payload.jti);
  db.prepare('INSERT OR IGNORE INTO revoked_tokens (jti) VALUES (?)').run(payload.jti);

  completeLogin(req, res, user, { usedBackupCode });
});

// ─────────────────────────────────────────────────
// POST /api/auth/verify-location  — confirm the emailed new-location code
// ─────────────────────────────────────────────────
router.post('/verify-location', validate(schemas.verifyLocation), (req, res) => {
  const { tempToken, code } = req.body;

  let payload;
  try { payload = jwt.verify(tempToken, process.env.JWT_SECRET); }
  catch { return E.unauthorized(res, 'Your verification session expired. Please sign in again.'); }
  if (!payload.pendingLocation) return E.badRequest(res, 'Invalid token type');

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.sub);
  if (!user) return E.unauthorized(res, 'Account not found');

  const codeHash = crypto.createHash('sha256').update(String(code)).digest('hex');
  const row = db.prepare(
    "SELECT * FROM login_codes WHERE user_id = ? AND code_hash = ? AND used = 0 AND datetime(expires_at) > datetime('now') ORDER BY id DESC LIMIT 1"
  ).get(user.id, codeHash);

  if (!row) {
    log(user.id, 'login_location_failed', 'Wrong or expired location code', req.ip);
    return E.unauthorized(res, 'That code is incorrect or has expired.');
  }

  db.prepare('UPDATE login_codes SET used = 1 WHERE id = ?').run(row.id);
  // completeLogin records this IP as known, so future logins from here are seamless.
  return completeLogin(req, res, user);
});

// ─────────────────────────────────────────────────
// POST /api/auth/refresh  — exchange refresh cookie for a new access token
// ─────────────────────────────────────────────────
router.post('/refresh', (req, res) => {
  const rawToken = req.cookies?.refreshToken;
  if (!rawToken) return E.unauthorized(res, 'No refresh token');

  const hash   = crypto.createHash('sha256').update(rawToken).digest('hex');
  const record = db.prepare(`
    SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked = 0 AND datetime(expires_at) > datetime('now')
  `).get(hash);

  if (!record) return E.unauthorized(res, 'Refresh token invalid or expired — please log in again');

  const user = db.prepare('SELECT id, email, name, role, plan, org_id FROM users WHERE id = ?').get(record.user_id);
  if (!user) return E.unauthorized(res, 'User not found');

  // Rotate: revoke old refresh token, issue new one
  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?').run(record.id);

  const expiresAt       = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const { token, jti }  = signAccess({ sub: user.id, email: user.email, name: user.name, role: user.role, plan: user.plan, org_id: user.org_id });

  // Reuse the existing session row (update its jti / last_used / expiry) instead of
  // inserting a new one on every refresh — otherwise the sessions table grows
  // unbounded and "last_used" never reflects activity. Fall back to creating one
  // only if the original session is gone (e.g. legacy refresh tokens).
  const updated = record.session_id
    ? db.prepare('UPDATE sessions SET jti = ?, expires_at = ?, last_used = CURRENT_TIMESTAMP, ip = ?, user_agent = ? WHERE id = ?')
        .run(jti, expiresAt, req.ip, req.headers['user-agent'], record.session_id).changes
    : 0;
  const sessionId = updated ? record.session_id : createSession(user.id, jti, req.ip, req.headers['user-agent'], expiresAt);

  const rawRefresh = crypto.randomBytes(40).toString('hex');
  storeRefreshToken(user.id, rawRefresh, sessionId);
  setRefreshCookie(res, rawRefresh);
  setAccessCookie(res, token);

  log(user.id, 'token_refreshed', 'Access token refreshed', req.ip);
  res.json({ token, user });
});

// ─────────────────────────────────────────────────
// POST /api/auth/logout
// ─────────────────────────────────────────────────
router.post('/logout', requireAuth, (req, res) => {
  // Revoke access token
  db.prepare('INSERT OR IGNORE INTO revoked_tokens (jti) VALUES (?)').run(req.user.jti);
  db.prepare('DELETE FROM sessions WHERE jti = ?').run(req.user.jti);

  // Revoke refresh token from cookie
  const rawRefresh = req.cookies?.refreshToken;
  if (rawRefresh) {
    const hash = crypto.createHash('sha256').update(rawRefresh).digest('hex');
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?').run(hash);
  }
  res.clearCookie('refreshToken', { path: '/api/auth' });
  res.clearCookie('access_token', { path: '/' });

  log(req.user.sub, 'logout', 'Logged out', req.ip);
  res.json({ message: 'Logged out' });
});

// ─────────────────────────────────────────────────
// GET /api/auth/me
// ─────────────────────────────────────────────────
router.get('/me', requireAuth, (req, res) => {
  const user = db.prepare(
    'SELECT id, email, name, role, plan, storage_used, totp_enabled, email_2fa, created_at, last_login FROM users WHERE id = ?'
  ).get(req.user.sub);
  if (!user) return E.notFound(res, 'User not found');
  // Surface the account-wide 2FA requirement so the UI can lock the toggle.
  user.require_2fa = getBool('require_2fa');
  res.json(user);
});

// POST /api/auth/email-2fa  — turn the user's own email two-factor on/off
router.post('/email-2fa', requireAuth, express.json(), (req, res) => {
  const enabled = req.body.enabled ? 1 : 0;
  // If an admin requires 2FA account-wide, users may turn it on but not off.
  if (!enabled && getBool('require_2fa')) {
    return E.forbidden(res, 'Your administrator requires two-factor authentication, so it can\'t be turned off.');
  }
  db.prepare('UPDATE users SET email_2fa = ? WHERE id = ?').run(enabled, req.user.sub);
  log(req.user.sub, 'email_2fa_changed', `Email 2FA ${enabled ? 'enabled' : 'disabled'}`, req.ip);
  res.json({ email_2fa: enabled, message: `Email two-factor authentication ${enabled ? 'enabled' : 'disabled'}.` });
});

// GET /api/auth/export  — download a JSON copy of all account data (GDPR-style)
router.get('/export', requireAuth, (req, res) => {
  const uid      = req.user.sub;
  const account  = db.prepare('SELECT id, email, name, role, plan, phone, storage_used, totp_enabled, email_2fa, created_at, last_login FROM users WHERE id = ?').get(uid);
  const folders  = db.prepare('SELECT id, name, created_at FROM folders WHERE user_id = ?').all(uid);
  const files    = db.prepare('SELECT id, name, size, mime_type, folder_id, uploaded_at, deleted_at FROM files WHERE user_id = ?').all(uid);
  const shares   = db.prepare('SELECT id, file_id, expires_at, downloads, max_downloads, revoked, created_at FROM file_shares WHERE user_id = ?').all(uid);
  const activity = db.prepare('SELECT action, detail, ip, created_at FROM activity_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 5000').all(uid);

  const payload = { exportedAt: new Date().toISOString(), account, folders, files, shares, activity };
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="nexus-account-data.json"');
  res.send(JSON.stringify(payload, null, 2));
});

// DELETE /api/auth/me  — permanently delete the signed-in user's account + all data
router.delete('/me', requireAuth, express.json(), async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  if (!user) return E.notFound(res, 'User not found');

  const ok = req.body.password && await bcrypt.compare(String(req.body.password), user.password_hash);
  if (!ok) return E.unauthorized(res, 'Password is incorrect.');

  // Free the file blobs from storage first (this part is async and can't run in a txn).
  const files = db.prepare('SELECT disk_path FROM files WHERE user_id = ?').all(user.id);
  for (const f of files) { if (f.disk_path) { try { await storage.remove(f.disk_path); } catch { /* keep going */ } } }

  // Remove every row that references this user, then the user itself.
  db.transaction(() => {
    for (const t of ['file_shares', 'files', 'folders', 'sessions', 'refresh_tokens',
                     'login_codes', 'password_reset_tokens', 'email_verifications',
                     'backup_codes', 'notifications', 'activity_log']) {
      try { db.prepare(`DELETE FROM ${t} WHERE user_id = ?`).run(user.id); } catch { /* table may not exist */ }
    }
    db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
  })();

  res.clearCookie('refreshToken', { path: '/api/auth' });
  res.clearCookie('access_token', { path: '/' });
  res.json({ message: 'Your account and all associated data have been permanently deleted.' });
});

// ─────────────────────────────────────────────────
// GET /api/auth/setup-2fa  — generate TOTP secret + QR code
// ─────────────────────────────────────────────────
router.get('/setup-2fa', requireAuth, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  if (user.totp_enabled) return E.conflict(res, '2FA is already enabled');

  const secret = speakeasy.generateSecret({ name: `Nexus Security (${user.email})`, length: 20 });
  db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(secret.base32, user.id);
  const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);
  res.json({ qrDataUrl, secret: secret.base32 });
});

// ─────────────────────────────────────────────────
// POST /api/auth/confirm-2fa  — verify first TOTP code to activate + return backup codes
// ─────────────────────────────────────────────────
router.post('/confirm-2fa', requireAuth, validate(schemas.confirmTotp), (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  if (!user.totp_secret) return E.badRequest(res, 'Start setup first: GET /api/auth/setup-2fa');

  const valid = speakeasy.totp.verify({ secret: user.totp_secret, encoding: 'base32', token: req.body.code.trim(), window: 1 });
  if (!valid) return E.unauthorized(res, 'Code is incorrect — make sure your authenticator app is synced');

  db.prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?').run(user.id);

  // Generate backup codes — shown ONCE, never retrievable again
  const rawCodes = generateBackupCodes();
  db.prepare('DELETE FROM backup_codes WHERE user_id = ?').run(user.id);
  const insert = db.prepare('INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)');
  rawCodes.forEach(code => insert.run(user.id, hashBackupCode(code)));

  log(user.id, 'totp_enabled', 'Authenticator 2FA enabled', req.ip);
  res.json({
    message: 'Authenticator 2FA is now active',
    backupCodes: rawCodes,
    warning: 'Save these backup codes somewhere safe — they will not be shown again. Each can only be used once.',
  });
});

// ─────────────────────────────────────────────────
// POST /api/auth/disable-2fa
// ─────────────────────────────────────────────────
router.post('/disable-2fa', requireAuth, validate(schemas.disableTotp), async (req, res) => {
  const user  = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  const match = await bcrypt.compare(req.body.password, user.password_hash);
  if (!match) return E.unauthorized(res, 'Incorrect password');

  db.prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?').run(user.id);
  db.prepare('DELETE FROM backup_codes WHERE user_id = ?').run(user.id);
  log(user.id, 'totp_disabled', 'Authenticator 2FA disabled', req.ip);
  res.json({ message: '2FA disabled. Your account now uses the email verification code.' });
});

// ─────────────────────────────────────────────────
// POST /api/auth/forgot-password
// ─────────────────────────────────────────────────
router.post('/forgot-password', validate(schemas.forgotPassword), async (req, res) => {
  const SAFE_RESPONSE = { message: 'If that email is in our system, a reset link has been sent.' };
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(req.body.email);
  if (!user) return res.json(SAFE_RESPONSE); // don't reveal whether email exists

  db.prepare('UPDATE password_reset_tokens SET used = 1 WHERE user_id = ?').run(user.id);

  const rawToken  = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

  db.prepare('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)').run(user.id, tokenHash, expiresAt);

  const base      = process.env.SITE_URL || `http://localhost:${process.env.PORT || 3000}`;
  const resetLink = `${base}/pages/reset-password.html?token=${rawToken}`;

  log(user.id, 'password_reset_requested', 'Reset link issued', req.ip);
  await alertPasswordResetRequested(user, resetLink);
  res.json(SAFE_RESPONSE);
});

// ─────────────────────────────────────────────────
// POST /api/auth/reset-password
// ─────────────────────────────────────────────────
router.post('/reset-password', validate(schemas.resetPassword), async (req, res) => {
  const { token, password } = req.body;
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const record    = db.prepare('SELECT * FROM password_reset_tokens WHERE token_hash = ? AND used = 0').get(tokenHash);

  if (!record || new Date(record.expires_at) < new Date()) {
    return sendError(res, 400, 'This reset link is invalid or has expired. Please request a new one.', 'TOKEN_EXPIRED');
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(record.user_id);
  if (!user) return E.notFound(res, 'User not found');

  const breaches = await isBreached(password);
  if (breaches)
    return sendError(res, 400, `This password has appeared in ${breaches.toLocaleString()} known data breaches. Please choose a different one.`, 'BREACHED_PASSWORD');

  const passwordHash = await bcrypt.hash(password, 12);
  db.prepare('UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL, force_password_reset = 0 WHERE id = ?').run(passwordHash, user.id);
  db.prepare('UPDATE password_reset_tokens SET used = 1 WHERE id = ?').run(record.id);

  // Invalidate all existing sessions for security
  const sessions = db.prepare('SELECT jti FROM sessions WHERE user_id = ?').all(user.id);
  sessions.forEach(s => db.prepare('INSERT OR IGNORE INTO revoked_tokens (jti) VALUES (?)').run(s.jti));
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').run(user.id);
  res.clearCookie('refreshToken', { path: '/api/auth' });
  res.clearCookie('access_token', { path: '/' });

  log(user.id, 'password_reset', 'Password reset successfully', req.ip);
  res.json({ message: 'Password updated. You can now log in with your new password.' });
});

// POST /api/auth/change-password
router.post('/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return E.badRequest(res, 'currentPassword and newPassword are required');
  if (newPassword.length < 8) return E.badRequest(res, 'New password must be at least 8 characters');

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  if (!user) return E.notFound(res, 'User not found');

  const match = await bcrypt.compare(currentPassword, user.password_hash);
  if (!match) return res.status(400).json({ error: 'Current password is incorrect' });

  if (await bcrypt.compare(newPassword, user.password_hash))
    return res.status(400).json({ error: 'New password must be different from your current password' });

  const breaches = await isBreached(newPassword);
  if (breaches)
    return res.status(400).json({ error: `This password has appeared in ${breaches.toLocaleString()} known data breaches. Please choose a different one.` });

  const hash = await bcrypt.hash(newPassword, 12);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
  log(user.id, 'password_change', 'Password changed via settings', req.ip);
  res.json({ message: 'Password updated successfully' });
});

module.exports = router;
