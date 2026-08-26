const cron = require('node-cron');
const db   = require('../db/database');
const logger = require('./logger');
const { driver: storage } = require('./storage');

const TRASH_RETENTION_DAYS = 30;

// These tables accumulate rows that are dead once expired/used. Without pruning
// they grow unbounded. revoked_tokens only needs to outlive the access-token
// lifetime; 30 days is a very safe margin even for long JWT_EXPIRES_IN values.
// Wrap stored timestamps in datetime() so ISO-8601 'Z' strings (how the app
// writes expires_at) and SQLite's space-separated format compare correctly —
// a raw string compare breaks for same-day timestamps ('T' vs ' ').
const SWEEPS = [
  ['sessions',              "DELETE FROM sessions WHERE datetime(expires_at) < datetime('now')"],
  ['revoked_tokens',        "DELETE FROM revoked_tokens WHERE datetime(revoked_at) < datetime('now','-30 days')"],
  ['refresh_tokens',        "DELETE FROM refresh_tokens WHERE revoked = 1 OR datetime(expires_at) < datetime('now')"],
  ['password_reset_tokens', "DELETE FROM password_reset_tokens WHERE used = 1 OR datetime(expires_at) < datetime('now')"],
  ['email_verifications',   "DELETE FROM email_verifications WHERE used = 1 OR datetime(expires_at) < datetime('now')"],
  ['login_codes',           "DELETE FROM login_codes WHERE used = 1 OR datetime(expires_at) < datetime('now')"],
];

// Permanently remove files that have sat in the Trash past the retention window.
// Each file's bytes are freed from storage and the owner's quota before the row
// is deleted — so this is the only path (besides manual "delete permanently")
// that actually reclaims space.
async function purgeExpiredTrash() {
  let purged = 0;
  let rows;
  try {
    rows = db.prepare(
      `SELECT id, user_id, size, disk_path, name FROM files
       WHERE deleted_at IS NOT NULL
         AND datetime(deleted_at) < datetime('now', ?)`
    ).all(`-${TRASH_RETENTION_DAYS} days`);
  } catch (err) {
    logger.error({ err }, '[cleanup] trash query failed');
    return 0;
  }
  for (const f of rows) {
    try {
      if (f.disk_path) { try { await storage.remove(f.disk_path); } catch { /* metadata removed anyway */ } }
      db.prepare('DELETE FROM files WHERE id = ?').run(f.id);
      db.prepare('UPDATE users SET storage_used = MAX(0, storage_used - ?) WHERE id = ?').run(f.size, f.user_id);
      purged++;
    } catch (err) {
      logger.error({ err }, `[cleanup] failed to purge file ${f.id}`);
    }
  }
  if (purged) logger.info(`[cleanup] trash: permanently purged ${purged} file(s) older than ${TRASH_RETENTION_DAYS} days`);
  return purged;
}

function runCleanup() {
  let total = 0;
  for (const [label, sql] of SWEEPS) {
    try {
      const info = db.prepare(sql).run();
      if (info.changes) {
        total += info.changes;
        logger.info(`[cleanup] ${label}: removed ${info.changes}`);
      }
    } catch (err) {
      logger.error({ err }, `[cleanup] ${label} failed`);
    }
  }
  // Fire-and-forget the async trash purge; failures are logged inside.
  purgeExpiredTrash().catch((err) => logger.error({ err }, '[cleanup] trash purge failed'));
  if (total === 0) logger.info('[cleanup] nothing to prune');
  return total;
}

function scheduleCleanup() {
  runCleanup();                       // once on startup
  cron.schedule('30 3 * * *', runCleanup); // then daily at 3:30 AM (after backups)
  logger.info('[cleanup] daily token/session cleanup scheduled for 3:30 AM');
}

module.exports = { scheduleCleanup, runCleanup, purgeExpiredTrash };
