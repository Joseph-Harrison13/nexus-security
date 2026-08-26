const jwt = require('jsonwebtoken');
const { getBool } = require('../lib/appSettings');

// When maintenance mode is on, the API returns 503 for everyone EXCEPT admins
// (so they can investigate and switch it back off) and the handful of auth
// endpoints needed to sign in. Static pages are served normally. This is the
// incident-response "take it offline fast" switch, toggled by an admin.
const ALWAYS_ALLOW = new Set([
  '/api/auth/login',
  '/api/auth/verify-2fa',
  '/api/auth/verify-location',
  '/api/auth/logout',
]);

function maintenanceGuard(req, res, next) {
  if (!getBool('maintenance_mode')) return next();

  // Only the platform owner (SuperAdmin) bypasses — maintenance is a platform-wide
  // outage they control; org admins are customers and see the maintenance page too.
  try {
    const h   = req.headers['authorization'] || '';
    const tok = (req.cookies && req.cookies.access_token) || (h.startsWith('Bearer ') ? h.slice(7) : null);
    if (tok) {
      const p = jwt.verify(tok, process.env.JWT_SECRET);
      const temp = p.pendingTwoFactor || p.pendingLocation || p.pendingTotpSetup;
      if (p.role === 'SuperAdmin' && !temp) return next();
    }
  } catch { /* not a valid superadmin token — fall through to the wall */ }

  const path = (req.originalUrl || '').split('?')[0];
  if (ALWAYS_ALLOW.has(path)) return next();

  return res.status(503).json({
    error: 'The service is temporarily unavailable for maintenance. Please try again shortly.',
    code:  'MAINTENANCE',
  });
}

module.exports = maintenanceGuard;
