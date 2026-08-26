const jwt = require('jsonwebtoken');
const db  = require('../db/database');

// Endpoints a user must be able to reach BEFORE they've set up 2FA, so they can
// actually enrol an authenticator app (or sign out). Everything else is blocked
// until TOTP is enabled — see the mandatory-2FA check below.
const TOTP_EXEMPT_PATHS = new Set([
  '/api/auth/setup-2fa',
  '/api/auth/confirm-2fa',
  '/api/auth/me',
  '/api/auth/logout',
]);

// Endpoints still reachable after a free trial has expired, so a locked-out org
// can view its account and upgrade to a paid plan (billing lives under /stripe).
const TRIAL_EXEMPT_PATHS = new Set([
  '/api/auth/me',
  '/api/auth/logout',
  '/api/auth/setup-2fa',
  '/api/auth/confirm-2fa',
]);
function isTrialExempt(path) {
  return TRIAL_EXEMPT_PATHS.has(path) || path.startsWith('/api/stripe/');
}

function requireAuth(req, res, next) {
  // Primary: httpOnly access_token cookie (not readable by JavaScript, so it
  // cannot be exfiltrated by XSS). Fallback: Authorization: Bearer header
  // (used by the test suite and any non-browser API clients).
  const header = req.headers['authorization'] || '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7) : null;
  const token  = (req.cookies && req.cookies.access_token) || bearer;

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  // Reject partial/temporary tokens — 2FA-pending, new-location, or TOTP-setup.
  // These are handed to the client mid-login and must NEVER authorize a normal
  // route, otherwise presenting one as a bearer would bypass the second factor.
  if (payload.pendingTwoFactor || payload.pendingLocation || payload.pendingTotpSetup) {
    return res.status(401).json({ error: 'Two-factor authentication required' });
  }

  // Check if this token has been explicitly revoked (logout)
  const revoked = db.prepare('SELECT jti FROM revoked_tokens WHERE jti = ?').get(payload.jti);
  if (revoked) {
    return res.status(401).json({ error: 'Token has been revoked' });
  }

  req.user = payload;

  // Current account + organization state (also catches a deleted-user token).
  const acct = db.prepare(`
    SELECT u.totp_enabled, u.suspended, o.subscription_status AS sub_status, o.trial_ends_at
    FROM users u LEFT JOIN organizations o ON u.org_id = o.id
    WHERE u.id = ?
  `).get(payload.sub);
  if (!acct) return res.status(401).json({ error: 'Account no longer exists' });

  // A suspended account is locked out of everything, immediately — including the
  // enrolment endpoints — regardless of any still-live token.
  if (acct.suspended) {
    return res.status(403).json({ error: 'This account has been suspended.', code: 'ACCOUNT_SUSPENDED' });
  }

  const path = (req.originalUrl || '').split('?')[0];

  // Free-trial expiry lock. A still-trialing org whose trial date has passed is
  // read-blocked until it upgrades to a paid plan. The platform owner is exempt,
  // and so are the account/billing endpoints (so they CAN upgrade).
  if (payload.role !== 'SuperAdmin' && !isTrialExempt(path)) {
    const trialExpired = acct.sub_status === 'trialing' && acct.trial_ends_at &&
      new Date(acct.trial_ends_at).getTime() < Date.now();
    if (trialExpired) {
      return res.status(402).json({
        error: 'Your free trial has ended. Upgrade to a monthly plan to keep using your account.',
        code:  'TRIAL_EXPIRED',
      });
    }
  }

  // Mandatory two-factor authentication. Until the account has an authenticator
  // app enabled, only the enrolment/bootstrap endpoints are reachable; every
  // data route is refused so a password alone is never enough to use the app.
  if (!TOTP_EXEMPT_PATHS.has(path) && !acct.totp_enabled) {
    return res.status(403).json({
      error: 'Two-factor authentication is required. Set up an authenticator app to continue.',
      code:  'TOTP_SETUP_REQUIRED',
    });
  }

  next();
}

// Org Admin (manages their own organization) OR the platform SuperAdmin.
function requireAdmin(req, res, next) {
  // requireAuth already enforces mandatory 2FA, so an admin without an
  // authenticator app is stopped there before ever reaching the admin surface.
  requireAuth(req, res, () => {
    if (req.user.role !== 'Admin' && req.user.role !== 'SuperAdmin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  });
}

// Platform owner only — cross-organization + platform-wide controls.
function requireSuperAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'SuperAdmin') {
      return res.status(403).json({ error: 'Platform administrator access required', code: 'SUPERADMIN_REQUIRED' });
    }
    next();
  });
}

// True when the caller may act across all organizations (no org scoping).
function isSuperAdmin(req) {
  return req.user && req.user.role === 'SuperAdmin';
}

module.exports = { requireAuth, requireAdmin, requireSuperAdmin, isSuperAdmin };
