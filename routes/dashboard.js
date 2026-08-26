const express = require('express');
const db      = require('../db/database');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { sendMail } = require('../lib/mailer');
const { csvRow } = require('../lib/csv');
const { getBool, getInt, setSetting } = require('../lib/appSettings');
const plans = require('../lib/plans');
const limits = require('../lib/limits');

const router = express.Router();

function bytesToGB(bytes) {
  return (bytes / (1024 ** 3)).toFixed(2);
}

// GET /api/dashboard/stats
router.get('/stats', requireAuth, (req, res) => {
  const userId  = req.user.sub;
  const orgId   = req.user.org_id;
  const isSuper = req.user.role === 'SuperAdmin';
  const isOrgAdmin = req.user.role === 'Admin';

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  const org  = db.prepare('SELECT plan FROM organizations WHERE id = ?').get(orgId) || { plan: user.plan };

  // Storage limits are per-organization (the org's plan).
  const limitGB    = limits.effectiveStorageGB(org.plan);
  const limitBytes = limits.effectiveStorageBytes(org.plan);

  let fileCount, storageUsed, totalUsers;
  if (isSuper) {
    fileCount   = db.prepare('SELECT COUNT(*) AS n FROM files').get().n;
    storageUsed = db.prepare('SELECT SUM(storage_used) AS total FROM users').get().total || 0;
    totalUsers  = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  } else if (isOrgAdmin) {
    fileCount   = db.prepare('SELECT COUNT(*) AS n FROM files WHERE org_id = ?').get(orgId).n;
    storageUsed = db.prepare('SELECT SUM(storage_used) AS total FROM users WHERE org_id = ?').get(orgId).total || 0;
    totalUsers  = db.prepare('SELECT COUNT(*) AS n FROM users WHERE org_id = ?').get(orgId).n;
  } else {
    fileCount   = db.prepare('SELECT COUNT(*) AS n FROM files WHERE user_id = ?').get(userId).n;
    storageUsed = user.storage_used;
    totalUsers  = 1;
  }

  const recentActivity = db.prepare(`
    SELECT action, detail, created_at
    FROM activity_log
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT 10
  `).all(userId);

  res.json({
    user: {
      name:         user.name,
      email:        user.email,
      role:         user.role,
      plan:         org.plan,
      lastLogin:    user.last_login,
    },
    storage: {
      usedBytes:   storageUsed,
      usedGB:      bytesToGB(storageUsed),
      limitGB,
      limitBytes,
      percentUsed: Math.min(100, Math.round((storageUsed / limitBytes) * 100)),
      thresholds:  plans.thresholds(org.plan),  // per-plan { warn, critical } %
    },
    counts: {
      files: fileCount,
      users: totalUsers,
    },
    recentActivity,
  });
});

// GET /api/dashboard/activity — paginated activity log
router.get('/activity', requireAuth, (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit,  10) || 20, 100);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0,  0);

  let rows;
  if (req.user.role === 'SuperAdmin') {
    rows = db.prepare(`
      SELECT l.*, u.email AS user_email
      FROM activity_log l LEFT JOIN users u ON l.user_id = u.id
      ORDER BY l.created_at DESC LIMIT ? OFFSET ?
    `).all(limit, offset);
  } else if (req.user.role === 'Admin') {
    rows = db.prepare(`
      SELECT l.*, u.email AS user_email
      FROM activity_log l JOIN users u ON l.user_id = u.id
      WHERE u.org_id = ?
      ORDER BY l.created_at DESC LIMIT ? OFFSET ?
    `).all(req.user.org_id, limit, offset);
  } else {
    rows = db.prepare(`
      SELECT * FROM activity_log WHERE user_id = ?
      ORDER BY created_at DESC LIMIT ? OFFSET ?
    `).all(req.user.sub, limit, offset);
  }

  res.json(rows);
});

// GET /api/dashboard/activity/export/csv — download activity history as a spreadsheet
router.get('/activity/export/csv', requireAuth, (req, res) => {
  const isAdmin = req.user.role === 'Admin' || req.user.role === 'SuperAdmin';
  let rows;
  if (req.user.role === 'SuperAdmin') {
    rows = db.prepare(`
      SELECT l.created_at, u.email AS user_email, l.action, l.detail, l.ip
      FROM activity_log l LEFT JOIN users u ON l.user_id = u.id
      ORDER BY l.created_at DESC LIMIT 5000
    `).all();
  } else if (req.user.role === 'Admin') {
    rows = db.prepare(`
      SELECT l.created_at, u.email AS user_email, l.action, l.detail, l.ip
      FROM activity_log l JOIN users u ON l.user_id = u.id
      WHERE u.org_id = ?
      ORDER BY l.created_at DESC LIMIT 5000
    `).all(req.user.org_id);
  } else {
    rows = db.prepare(`
      SELECT created_at, action, detail, ip
      FROM activity_log WHERE user_id = ?
      ORDER BY created_at DESC LIMIT 5000
    `).all(req.user.sub);
  }

  const header = isAdmin
    ? 'date,user,action,detail,ip\n'
    : 'date,action,detail,ip\n';
  const body = rows.map(r => isAdmin
    ? csvRow([r.created_at, r.user_email || '', r.action, r.detail || '', r.ip || ''])
    : csvRow([r.created_at, r.action, r.detail || '', r.ip || ''])
  ).join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="activity-history.csv"');
  res.send(header + body);
});

// GET /api/dashboard/org-settings — account-wide settings (any signed-in user)
router.get('/org-settings', requireAuth, (req, res) => {
  res.json({
    require2fa:        getBool('require_2fa'),
    seatOverride:      getInt('seat_override'),
    storageOverrideGb: getInt('storage_override_gb'),
    mailboxOverride:   getInt('mailbox_override'),
    planDefaults: {
      seats:     plans.seatLimit(req.user.plan),
      storageGb: plans.limitGB(req.user.plan),
      mailboxes: plans.mailboxLimit(req.user.plan),
    },
  });
});

// POST /api/dashboard/account-limits — admin sets per-account overrides.
// An empty / 0 value clears the override (falls back to the plan default).
router.post('/account-limits', requireAdmin, express.json(), (req, res) => {
  const fields = { seat_override: 'seatOverride', storage_override_gb: 'storageOverrideGb', mailbox_override: 'mailboxOverride' };
  for (const [key, bodyKey] of Object.entries(fields)) {
    const raw = req.body[bodyKey];
    const n = parseInt(raw, 10);
    setSetting(key, Number.isFinite(n) && n > 0 ? n : '');
  }
  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.sub, 'account_limits_changed', 'Updated per-account limit overrides', req.ip);
  res.json({
    message: 'Account limits updated.',
    seatOverride:      getInt('seat_override'),
    storageOverrideGb: getInt('storage_override_gb'),
    mailboxOverride:   getInt('mailbox_override'),
  });
});

// POST /api/dashboard/require-2fa — admin toggles the account-wide 2FA requirement
router.post('/require-2fa', requireAdmin, express.json(), (req, res) => {
  const enabled = req.body.enabled ? 1 : 0;
  setSetting('require_2fa', enabled);
  // Turning it on forces email 2FA back on for everyone so the rule actually holds.
  if (enabled) db.prepare('UPDATE users SET email_2fa = 1').run();
  db.prepare('INSERT INTO activity_log (user_id, action, detail, ip) VALUES (?, ?, ?, ?)')
    .run(req.user.sub, 'require_2fa_changed', `Account-wide 2FA requirement ${enabled ? 'enabled' : 'disabled'}`, req.ip);
  res.json({ require2fa: !!enabled, message: `Two-factor authentication is now ${enabled ? 'required for all team members' : 'optional'}.` });
});

// GET /api/dashboard/security-score
router.get('/security-score', requireAuth, (req, res) => {
  const userId = req.user.sub;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);

  const factors = [];
  let score = 0;

  // 2FA enabled (+35)
  if (user.totp_enabled) {
    score += 35;
    factors.push({ label: '2FA enabled', points: 35, passed: true });
  } else {
    factors.push({ label: '2FA not enabled', points: 35, passed: false, action: 'Enable two-factor authentication in Settings' });
  }

  // Known IP on record (+20)
  const knownIpCount = user.known_ips ? JSON.parse(user.known_ips).length : 0;
  if (knownIpCount > 0) {
    score += 20;
    factors.push({ label: 'Trusted devices registered', points: 20, passed: true });
  } else {
    factors.push({ label: 'No trusted devices', points: 20, passed: false, action: 'Log in from your usual devices to register them' });
  }

  // Recent login (active account) (+15)
  const lastLogin = user.last_login ? new Date(user.last_login) : null;
  const daysSince = lastLogin ? (Date.now() - lastLogin.getTime()) / (1000 * 60 * 60 * 24) : 999;
  if (daysSince < 30) {
    score += 15;
    factors.push({ label: 'Account actively monitored', points: 15, passed: true });
  } else {
    factors.push({ label: 'Account inactive >30 days', points: 15, passed: false, action: 'Log in regularly to keep monitoring active' });
  }

  // Has uploaded files (using service) (+15)
  const fileCount = db.prepare('SELECT COUNT(*) AS n FROM files WHERE user_id = ?').get(userId).n;
  if (fileCount > 0) {
    score += 15;
    factors.push({ label: 'Files stored & protected', points: 15, passed: true });
  } else {
    factors.push({ label: 'No files stored yet', points: 15, passed: false, action: 'Upload your important files to secure them' });
  }

  // Password not recently failed (no locked account) (+15)
  if (!user.locked_until || new Date(user.locked_until) < new Date()) {
    score += 15;
    factors.push({ label: 'No failed login attempts', points: 15, passed: true });
  } else {
    factors.push({ label: 'Account recently locked', points: 15, passed: false, action: 'Review recent login attempts in your activity log' });
  }

  let grade, color;
  if (score >= 90)      { grade = 'Excellent'; color = '#7ec99b'; }
  else if (score >= 70) { grade = 'Good';      color = '#3B82F6'; }
  else if (score >= 50) { grade = 'Fair';      color = '#c8a96e'; }
  else                  { grade = 'At Risk';   color = '#ef4444'; }

  res.json({ score, grade, color, factors });
});

// POST /api/dashboard/test-email  — admin: send a test email to verify SMTP config
router.post('/test-email', requireAdmin, async (req, res) => {
  const configured = !!process.env.EMAIL_USER && process.env.EMAIL_USER !== 'your@email.com' && !!process.env.EMAIL_PASS;
  if (!configured) {
    return res.status(503).json({ error: 'Email is not configured. Add EMAIL_USER, EMAIL_PASS, and EMAIL_HOST to your .env file.' });
  }
  const dest = process.env.EMAIL_TO || process.env.EMAIL_USER;
  const sent = await sendMail({
    to:      dest,
    subject: 'Nexus Security — Test Email',
    text:    'This is a test email from your Nexus Security server. SMTP is working correctly.',
    html:    '<p style="font-family:sans-serif">This is a test email from your <strong>Nexus Security</strong> server. SMTP is working correctly.</p>',
  });
  if (sent) {
    res.json({ message: `Test email sent to ${dest}` });
  } else {
    res.status(500).json({ error: 'Email send failed. Check your SMTP credentials and server logs.' });
  }
});

module.exports = router;
