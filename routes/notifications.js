const express  = require('express');
const webpush  = require('web-push');
const db       = require('../db/database');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const router = express.Router();

// Configure VAPID
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(
    process.env.VAPID_SUBJECT || 'mailto:admin@localhost',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
}

// SSRF guard. A push endpoint is a URL the server itself will later POST to, so
// an unvalidated one lets a user aim the server at internal hosts (e.g. cloud
// metadata at 169.254.169.254). Only accept HTTPS URLs on a known Web Push
// provider — an allowlist is safe against IP-parsing/DNS-rebinding tricks in a
// way that blocklisting private ranges is not.
const ALLOWED_PUSH_HOSTS = [
  'fcm.googleapis.com',          // Chrome, Edge, Opera (FCM)
  'android.googleapis.com',      // legacy GCM
  '.push.services.mozilla.com',  // Firefox
  '.notify.windows.com',         // Windows / Edge (WNS)
  '.push.apple.com',             // Safari
];
function isValidPushEndpoint(raw) {
  let url;
  try { url = new URL(String(raw)); } catch { return false; }
  if (url.protocol !== 'https:') return false;
  const host = url.hostname.toLowerCase();
  return ALLOWED_PUSH_HOSTS.some(h => (h.startsWith('.') ? host.endsWith(h) : host === h));
}

// GET /api/notifications
router.get('/', requireAuth, (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit, 10) || 20, 100);
  const rows   = db.prepare(`
    SELECT * FROM notifications WHERE user_id = ?
    ORDER BY created_at DESC LIMIT ?
  `).all(req.user.sub, limit);
  const unreadCount = db.prepare('SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read_at IS NULL').get(req.user.sub).n;
  res.json({ notifications: rows, unreadCount });
});

// POST /api/notifications/read-all
router.post('/read-all', requireAuth, (req, res) => {
  db.prepare('UPDATE notifications SET read_at = CURRENT_TIMESTAMP WHERE user_id = ? AND read_at IS NULL').run(req.user.sub);
  res.json({ message: 'All marked read' });
});

// POST /api/notifications/:id/read
router.post('/:id/read', requireAuth, (req, res) => {
  db.prepare('UPDATE notifications SET read_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?').run(req.params.id, req.user.sub);
  res.json({ message: 'Marked read' });
});

// GET /api/notifications/vapid-public-key  — browser needs this to subscribe
router.get('/vapid-public-key', requireAuth, (req, res) => {
  if (!process.env.VAPID_PUBLIC_KEY) return res.status(503).json({ error: 'Push not configured' });
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
});

// POST /api/notifications/subscribe
router.post('/subscribe', requireAuth, express.json(), (req, res) => {
  const { endpoint, keys } = req.body;
  if (!endpoint || !keys) return res.status(400).json({ error: 'Invalid subscription object' });
  if (!isValidPushEndpoint(endpoint)) return res.status(400).json({ error: 'Unrecognized push service endpoint' });
  db.prepare(`
    INSERT INTO push_subscriptions (user_id, endpoint, keys)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id, endpoint) DO UPDATE SET keys = excluded.keys
  `).run(req.user.sub, endpoint, JSON.stringify(keys));
  res.json({ message: 'Subscribed' });
});

// DELETE /api/notifications/subscribe  — unsubscribe
router.delete('/subscribe', requireAuth, express.json(), (req, res) => {
  const { endpoint } = req.body;
  if (endpoint) {
    db.prepare('DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?').run(req.user.sub, endpoint);
  } else {
    db.prepare('DELETE FROM push_subscriptions WHERE user_id = ?').run(req.user.sub);
  }
  res.json({ message: 'Unsubscribed' });
});

// GET /api/notifications/push-status  — is this user subscribed?
router.get('/push-status', requireAuth, (req, res) => {
  const count = db.prepare('SELECT COUNT(*) AS n FROM push_subscriptions WHERE user_id = ?').get(req.user.sub).n;
  res.json({ subscribed: count > 0, vapidConfigured: !!process.env.VAPID_PUBLIC_KEY });
});

// POST /api/notifications/send  — admin: send push to a user or all users
router.post('/send', requireAdmin, express.json(), async (req, res) => {
  const { userId, title, body, icon } = req.body;
  if (!title || !body) return res.status(400).json({ error: 'title and body are required' });

  const subs = userId
    ? db.prepare('SELECT * FROM push_subscriptions WHERE user_id = ?').all(userId)
    : db.prepare('SELECT * FROM push_subscriptions').all();

  const payload = JSON.stringify({ title, body, icon: icon || '/icons/icon-192.png' });
  const results = await Promise.allSettled(subs.map(sub =>
    webpush.sendNotification({ endpoint: sub.endpoint, keys: JSON.parse(sub.keys) }, payload)
      .catch(err => {
        if (err.statusCode === 410) {
          db.prepare('DELETE FROM push_subscriptions WHERE id = ?').run(sub.id);
        }
        throw err;
      })
  ));

  const sent   = results.filter(r => r.status === 'fulfilled').length;
  const failed = results.filter(r => r.status === 'rejected').length;
  res.json({ sent, failed, total: subs.length });
});

// Helper exported so other routes can create in-app notifications
function createNotification(userId, type, icon, message) {
  try {
    db.prepare('INSERT INTO notifications (user_id, type, icon, message) VALUES (?, ?, ?, ?)').run(userId, type, icon, message);
  } catch { /* non-fatal */ }
}

// Helper to push to all of a user's push subscriptions
async function pushToUser(userId, title, body) {
  if (!process.env.VAPID_PUBLIC_KEY) return;
  const subs = db.prepare('SELECT * FROM push_subscriptions WHERE user_id = ?').all(userId);
  const payload = JSON.stringify({ title, body, icon: '/icons/icon-192.png' });
  await Promise.allSettled(subs.map(sub =>
    webpush.sendNotification({ endpoint: sub.endpoint, keys: JSON.parse(sub.keys) }, payload)
      .catch(err => {
        if (err.statusCode === 410) db.prepare('DELETE FROM push_subscriptions WHERE id = ?').run(sub.id);
      })
  ));
}

module.exports = router;
module.exports.createNotification = createNotification;
module.exports.pushToUser = pushToUser;
